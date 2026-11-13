const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false }, max: 5 });
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const code = () => 'MAX-' + crypto.randomBytes(12).toString('hex').toUpperCase();
const safeEqual = (a,b) => { const x=Buffer.from(a||''); const y=Buffer.from(b||''); return x.length===y.length && crypto.timingSafeEqual(x,y); };
const admin = (req,res,next) => safeEqual(req.get('x-admin-secret'),process.env.ADMIN_SECRET) && process.env.ADMIN_SECRET ? next() : res.status(403).json({error:'Forbidden'});
const deviceOk = x => typeof x === 'string' && /^[a-f0-9]{64}$/i.test(x);
const token = () => crypto.randomBytes(32).toString('hex');
const loginLimiter = new Map();
function limit(req,res,next) {
  const key = req.ip + ':' + req.path;
  const now=Date.now(); const old=loginLimiter.get(key);
  const entry= !old || old.until<now ? {count:0,until:now+15*60*1000} : old;
  entry.count++; loginLimiter.set(key,entry);
  if(loginLimiter.size>5000) for(const [k,v] of loginLimiter) if(v.until<now) loginLimiter.delete(k);
  if(entry.count>20) return res.status(429).json({error:'Too many attempts; retry later'});
  next();
}

app.get('/', (_req,res)=>res.json({app:'MAX TV',status:'online'}));
app.get('/api/health', async (_req,res)=>{try{await pool.query('SELECT 1');res.json({status:'ok',database:'connected'});}catch(e){console.error('DATABASE ERROR:',e.message);res.status(503).json({status:'error',database:'disconnected'});}});

// Call once only; existing 200 codes are preserved.
app.post('/api/admin/generate-codes',admin,async(_req,res)=>{
 const client=await pool.connect();
 try {await client.query('BEGIN'); const codes=[];
  for(const days of [30,90]) for(let i=0;i<100;i++) {const value=code();await client.query('INSERT INTO public.max_tv_activation_codes(code_hash,duration_days) VALUES($1,$2)',[sha(value),days]);codes.push({code:value,duration_days:days});}
  await client.query('COMMIT');res.json({created:codes.length,codes});
 }catch(e){await client.query('ROLLBACK');console.error(e);res.status(500).json({error:'Generation failed'});}finally{client.release();}
});

app.post('/api/activate',limit,async(req,res)=>{
 const {username,password,code:activationCode,device_hash}=req.body||{};
 if(typeof username!=='string'|| !/^[a-zA-Z0-9_]{3,32}$/.test(username)||typeof password!=='string'||password.length<12||password.length>128||typeof activationCode!=='string'|| !/^MAX-[A-F0-9]{24}$/.test(activationCode)||!deviceOk(device_hash)) return res.status(400).json({error:'Invalid input'});
 const passHash=await bcrypt.hash(password,12);
 const client=await pool.connect();
 try {await client.query('BEGIN');
  const activation=await client.query('SELECT id,duration_days FROM public.max_tv_activation_codes WHERE code_hash=$1 AND user_id IS NULL FOR UPDATE',[sha(activationCode)]);
  if(!activation.rowCount){await client.query('ROLLBACK');return res.status(400).json({error:'Invalid or used code'});}
  const user=(await client.query('INSERT INTO public.max_tv_users(username,password_hash) VALUES($1,$2) RETURNING id,username',[username,passHash])).rows[0];
  await client.query("UPDATE public.max_tv_activation_codes SET user_id=$1,activated_at=NOW(),expires_at=NOW()+($2 * INTERVAL '1 day') WHERE id=$3",[user.id,activation.rows[0].duration_days,activation.rows[0].id]);
  await client.query('INSERT INTO public.max_tv_devices(user_id,device_hash,device_slot) VALUES($1,$2,1)',[user.id,device_hash.toLowerCase()]);
  const session=token(); await client.query('INSERT INTO public.max_tv_sessions(user_id,device_hash,token_hash,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL \'30 days\')',[user.id,device_hash.toLowerCase(),sha(session)]);
  await client.query('COMMIT');res.status(201).json({success:true,username:user.username,duration_days:activation.rows[0].duration_days,session_token:session});
 }catch(e){await client.query('ROLLBACK');if(e.code==='23505')return res.status(409).json({error:'Username already exists'});console.error(e);res.status(500).json({error:'Activation failed'});}finally{client.release();}
});

app.post('/api/login',limit,async(req,res)=>{
 const {username,password,device_hash}=req.body||{};
 if(typeof username!=='string'||typeof password!=='string'||!deviceOk(device_hash))return res.status(400).json({error:'Invalid input'});
 const client=await pool.connect();
 try {const userResult=await client.query('SELECT id,username,password_hash FROM public.max_tv_users WHERE username=$1',[username]);
  const user=userResult.rows[0];if(!user||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:'Invalid credentials'});
  await client.query('BEGIN');
  const sub=await client.query('SELECT expires_at FROM public.max_tv_activation_codes WHERE user_id=$1 AND expires_at>NOW() FOR UPDATE',[user.id]);
  if(!sub.rowCount){await client.query('ROLLBACK');return res.status(403).json({error:'Subscription expired'});}
  const devices=await client.query('SELECT device_hash,device_slot FROM public.max_tv_devices WHERE user_id=$1 FOR UPDATE',[user.id]);
  const normalized=device_hash.toLowerCase();
  if(!devices.rows.some(d=>d.device_hash===normalized)){
   const used=new Set(devices.rows.map(d=>d.device_slot));const slot=[1,2,3].find(n=>!used.has(n));
   if(!slot){await client.query('ROLLBACK');return res.status(403).json({error:'Device limit reached (3)'});}
   await client.query('INSERT INTO public.max_tv_devices(user_id,device_hash,device_slot) VALUES($1,$2,$3)',[user.id,normalized,slot]);
  }
  await client.query('UPDATE public.max_tv_devices SET last_seen_at=NOW() WHERE user_id=$1 AND device_hash=$2',[user.id,normalized]);
  const session=token();await client.query('INSERT INTO public.max_tv_sessions(user_id,device_hash,token_hash,expires_at) VALUES($1,$2,$3,NOW()+INTERVAL \'30 days\')',[user.id,normalized,sha(session)]);
  await client.query('COMMIT');res.json({success:true,username:user.username,session_token:session,expires_at:sub.rows[0].expires_at});
 }catch(e){await client.query('ROLLBACK').catch(()=>{});console.error(e);res.status(500).json({error:'Login failed'});}finally{client.release();}
});

async function auth(req,res,next){
 const bearer=req.get('authorization')||'';const match=/^Bearer ([a-f0-9]{64})$/i.exec(bearer);
 if(!match)return res.status(401).json({error:'Unauthorized'});
 try{const result=await pool.query(`SELECT s.user_id,s.device_hash,u.username,a.expires_at
 FROM public.max_tv_sessions s JOIN public.max_tv_users u ON u.id=s.user_id
 JOIN public.max_tv_devices d ON d.user_id=s.user_id AND d.device_hash=s.device_hash
 JOIN public.max_tv_activation_codes a ON a.user_id=s.user_id
 WHERE s.token_hash=$1 AND s.expires_at>NOW() AND a.expires_at>NOW()`,[sha(match[1])]);
 if(!result.rowCount)return res.status(401).json({error:'Session invalid or subscription expired'});
 req.account=result.rows[0];next();
 }catch(e){console.error(e);res.status(500).json({error:'Authentication failed'});}
}
app.get('/api/me',auth,(req,res)=>res.json({username:req.account.username,expires_at:req.account.expires_at,max_devices:3}));
app.post('/api/logout',auth,async(req,res)=>{await pool.query('DELETE FROM public.max_tv_sessions WHERE token_hash=$1',[sha(req.get('authorization').slice(7))]);res.json({success:true});});

const PORT=process.env.PORT||3000;
app.listen(PORT,'0.0.0.0',()=>console.log('MAX TV Server running on '+PORT));
