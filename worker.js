// Serveur de vérification + pont de connexion OAuth (Cloudflare Workers, gratuit).
//
// 1) Vérification de pseudo : reçoit ?u=pseudo&p=plateforme, répond {"available":true|false}.
// 2) Connexion par compte (GitHub / Twitter-X / Roblox) : reçoit le retour de la plateforme
//    sur /oauth/<plateforme>/callback, échange le code contre un profil, puis redirige
//    le navigateur vers le site avec le profil dans l'URL (après #, jamais envoyé à un serveur).
//
// Les clés secrètes ne sont JAMAIS dans ce fichier ni dans le site : configure-les comme
// variables d'environnement de ce worker (Cloudflare Dashboard > Settings > Variables,
// ou `wrangler secret put`). Variables possibles :
//   GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
//   TWITTER_CLIENT_ID, TWITTER_CLIENT_SECRET
//   ROBLOX_CLIENT_ID, ROBLOX_CLIENT_SECRET
// Le Client ID de chaque appli doit être le MÊME que celui enregistré dans l'onglet Admin
// du site (c'est public, ce n'est pas un secret). Le Client Secret, lui, ne sort jamais d'ici.
//
// Dans chaque plateforme (GitHub / Twitter-X / Roblox), la Redirect URI à enregistrer est :
//   <url de ce worker>/oauth/github/callback
//   <url de ce worker>/oauth/twitter/callback
//   <url de ce worker>/oauth/roblox/callback
// (l'onglet Admin du site affiche ces 3 adresses une fois "Mon serveur" renseigné)

const CORS={'Access-Control-Allow-Origin':'*','Content-Type':'application/json'};
const out=(o,s=200,h={})=>new Response(JSON.stringify(o),{status:s,headers:{...CORS,...h}});
const b64url=s=>btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const fromB64=s=>{try{return JSON.parse(atob(s))}catch(e){return null}};

async function exchangeGithub(code,ru,env){
 const r=await fetch('https://github.com/login/oauth/access_token',{method:'POST',
  headers:{'Content-Type':'application/json','Accept':'application/json'},
  body:JSON.stringify({client_id:env.GITHUB_CLIENT_ID,client_secret:env.GITHUB_CLIENT_SECRET,code,redirect_uri:ru})});
 const j=await r.json();if(!j.access_token)throw new Error(j.error_description||'échange GitHub échoué');
 const u=await fetch('https://api.github.com/user',{headers:{Authorization:'Bearer '+j.access_token,'User-Agent':'2kr-checker'}}).then(x=>x.json());
 if(!u.id)throw new Error('profil GitHub introuvable');
 return{id:u.id,n:u.login,a:u.avatar_url||''};
}
async function exchangeTwitter(code,ru,verifier,env){
 const basic=btoa(env.TWITTER_CLIENT_ID+':'+env.TWITTER_CLIENT_SECRET);
 const body=new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:ru,code_verifier:verifier,client_id:env.TWITTER_CLIENT_ID});
 const r=await fetch('https://api.twitter.com/2/oauth2/token',{method:'POST',
  headers:{'Content-Type':'application/x-www-form-urlencoded','Authorization':'Basic '+basic},body});
 const j=await r.json();if(!j.access_token)throw new Error(j.error_description||'échange Twitter/X échoué');
 const u=await fetch('https://api.twitter.com/2/users/me?user.fields=profile_image_url',{headers:{Authorization:'Bearer '+j.access_token}}).then(x=>x.json());
 if(!u.data||!u.data.id)throw new Error('profil Twitter/X introuvable');
 return{id:u.data.id,n:u.data.username,a:u.data.profile_image_url||''};
}
async function exchangeRoblox(code,ru,verifier,env){
 const body=new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:ru,code_verifier:verifier,
  client_id:env.ROBLOX_CLIENT_ID,client_secret:env.ROBLOX_CLIENT_SECRET});
 const r=await fetch('https://apis.roblox.com/oauth/v1/token',{method:'POST',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},body});
 const j=await r.json();if(!j.access_token)throw new Error(j.error_description||'échange Roblox échoué');
 const u=await fetch('https://apis.roblox.com/oauth/v1/userinfo',{headers:{Authorization:'Bearer '+j.access_token}}).then(x=>x.json());
 if(!u.sub)throw new Error('profil Roblox introuvable');
 return{id:u.sub,n:u.preferred_username||u.name||u.sub,a:u.picture||''};
}

async function handleCallback(platform,url,env){
 const q=url.searchParams,code=q.get('code'),state=fromB64(q.get('state')||'');
 const ru=url.origin+url.pathname; // doit correspondre exactement à la redirect_uri envoyée
 if(!state||!state.return)return out({error:'state manquant ou invalide'},400);
 const back=u=>Response.redirect(state.return+'#'+u,302);
 if(!code)return back('oe='+platform);
 try{
  let profile;
  if(platform==='github')profile=await exchangeGithub(code,ru,env);
  else if(platform==='twitter')profile=await exchangeTwitter(code,ru,state.verifier,env);
  else if(platform==='roblox')profile=await exchangeRoblox(code,ru,state.verifier,env);
  else return out({error:'plateforme inconnue'},404);
  const key={github:'gh',twitter:'tw',roblox:'rb'}[platform];
  return back(key+'='+b64url(JSON.stringify(profile)));
 }catch(e){return back('oe='+platform)}
}

// ===== Utilisateurs, IP / région et clés liées à un pseudo =====
// Nécessite un KV Namespace lié à ce worker sous le nom « KR » (voir LISEZMOI).
// Les routes /api/admin/* exigent une signature de l'admin (même clé privée que le site).
const ADMIN_PUB={"kty": "EC", "crv": "P-256", "x": "1dXFdekT3anlosYRdZPTMi1DtMT6Y06BM9gCWm7T0RQ", "y": "5OoFcI8GNO3uRgjMLRWAFXe81iLMJ11kJGIVy5X6zTU"};
const sha256=async s=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)))].map(b=>b.toString(16).padStart(2,'0')).join('');
async function adminOK(req,path,body){
 const ts=req.headers.get('X-Ts'),sg=req.headers.get('X-Sig');if(!ts||!sg||Math.abs(Date.now()-(+ts))>300000)return false;
 try{const k=await crypto.subtle.importKey('jwk',ADMIN_PUB,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},k,Uint8Array.from(atob(sg),c=>c.charCodeAt(0)),new TextEncoder().encode(ts+'\n'+path+'\n'+body))}catch(e){return false}}
async function listAll(env,prefix){const o=[];let cursor;do{const r=await env.KR.list({prefix,cursor});for(const k of r.keys){const v=await env.KR.get(k.name);if(v)o.push({name:k.name,v:JSON.parse(v)})}cursor=r.list_complete?undefined:r.cursor}while(cursor&&o.length<1000);return o}
async function api(req,env,url){
 if(!env.KR)return out({error:'KV non configuré (binding KR)'},500);
 const path=url.pathname,body=req.method==='POST'?await req.text():'';let j={};try{j=body?JSON.parse(body):{}}catch(e){}
 const cf=req.cf||{},geo={ip:req.headers.get('CF-Connecting-IP')||'',country:cf.country||'',region:cf.region||'',city:cf.city||''};
 const okP=p=>typeof p==='string'&&p.trim().length>=2&&p.trim().length<=24;
 const seen=async(pseudo,kid,via)=>{const id='user:'+encodeURIComponent(pseudo.toLowerCase());
  const o=JSON.parse(await env.KR.get(id)||'null')||{first:Date.now(),n:0};
  await env.KR.put(id,JSON.stringify({...o,pseudo,kid,via,...geo,last:Date.now(),n:(o.n||0)+1}));return o.role||'membre'};
 const roleOf=async p=>(JSON.parse(await env.KR.get('user:'+encodeURIComponent(p.toLowerCase()))||'null')||{}).role||'membre';
 if(path==='/api/login'||path==='/api/ping'){
  const k=String(j.k||''),p=String(j.pseudo||'').trim();
  if(!/^\d{8}$/.test(k)||!okP(p))return out({error:'invalid'},401);
  const hk='key:'+await sha256('kr:'+k),r=JSON.parse(await env.KR.get(hk)||'null');
  if(!r||r.pseudo.toLowerCase()!==p.toLowerCase())return out({error:'invalid'},401);
  if(r.rev)return out({error:'revoked'},401);
  const role=await roleOf(r.pseudo);if(role==='bloque')return out({error:'blocked'},401);
  if(path==='/api/login'){r.uses=(r.uses||0)+1;r.last=Date.now();await env.KR.put(hk,JSON.stringify(r));await seen(r.pseudo,r.id,'key')}
  return out({ok:true,pseudo:r.pseudo,role});
 }
 if(path==='/api/seen'){ // clés classiques / admin : on enregistre juste pseudo + IP + région
  if(!okP(j.pseudo))return out({error:'invalid'},400);
  const role=await seen(String(j.pseudo).trim(),j.kid,'legacy');return out({ok:true,role});
 }
 if(path==='/api/role'){
  if(!okP(j.pseudo))return out({error:'invalid'},400);
  return out({ok:true,role:await roleOf(String(j.pseudo).trim())});
 }
 if(path.startsWith('/api/admin/')){
  if(!await adminOK(req,path,body))return out({error:'admin requis'},403);
  if(path==='/api/admin/users'){const l=await listAll(env,'user:');return out({users:l.map(x=>x.v).sort((a,b)=>b.last-a.last)})}
  if(path==='/api/admin/users/role'){
   if(!['membre','vip','modo','bloque'].includes(j.role))return out({error:'rôle invalide'},400);
   const id='user:'+encodeURIComponent(String(j.pseudo||'').toLowerCase()),o=JSON.parse(await env.KR.get(id)||'null');
   if(!o)return out({error:'introuvable'},404);o.role=j.role;await env.KR.put(id,JSON.stringify(o));return out({ok:true});
  }
  if(path==='/api/admin/users/del'){await env.KR.delete('user:'+encodeURIComponent(String(j.pseudo||'').toLowerCase()));return out({ok:true})}
  if(path==='/api/admin/keys'&&req.method==='GET'){const l=await listAll(env,'key:');return out({keys:l.map(x=>x.v).sort((a,b)=>b.created-a.created)})}
  if(path==='/api/admin/keys'&&req.method==='POST'){
   if(!okP(j.pseudo))return out({error:'pseudo invalide'},400);
   let key,hk;for(let i=0;i<5;i++){key=String(crypto.getRandomValues(new Uint32Array(1))[0]%90000000+10000000);hk='key:'+await sha256('kr:'+key);if(!await env.KR.get(hk))break}
   const r={id:hk.slice(4,16),pseudo:String(j.pseudo).trim(),key,created:Date.now(),rev:0,uses:0};
   await env.KR.put(hk,JSON.stringify(r));return out(r);
  }
  if(path==='/api/admin/keys/rev'||path==='/api/admin/keys/del'){
   const id=String(j.id||'').replace(/[^0-9a-f]/g,'');if(id.length<12)return out({error:'id'},400);
   const f=(await env.KR.list({prefix:'key:'+id})).keys[0];if(!f)return out({error:'introuvable'},404);
   if(path.endsWith('/del'))await env.KR.delete(f.name);
   else{const r=JSON.parse(await env.KR.get(f.name));r.rev=j.rev?1:0;await env.KR.put(f.name,JSON.stringify(r))}
   return out({ok:true});
  }
 }
 return out({error:'route inconnue'},404);
}

export default {
 async fetch(req,env){
  if(req.method==='OPTIONS')return new Response(null,{headers:{...CORS,'Access-Control-Allow-Headers':'*'}});
  const url=new URL(req.url);
  const m=url.pathname.match(/^\/oauth\/(github|twitter|roblox)\/callback$/);
  if(m)return handleCallback(m[1],url,env);
  if(url.pathname.startsWith('/api/'))return api(req,env,url);

  const q=url.searchParams;
  const u=(q.get('u')||'').trim(),p=q.get('p')||'Discord';
  if(!u||u.length>32)return out({error:'pseudo manquant ou trop long'},400);

  if(p==='Discord'){
   const r=await fetch('https://discord.com/api/v9/unique-username/username-attempt-unauthed',{
    method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.toLowerCase()})});
   if(r.status===429){const j=await r.json().catch(()=>({}));return out({error:'limite Discord'},429,{'Retry-After':String(Math.ceil(j.retry_after||10))})}
   if(r.status===400)return out({available:false});
   const j=await r.json().catch(()=>({}));
   return typeof j.taken==='boolean'?out({available:!j.taken}):out({error:'réponse Discord inattendue ('+r.status+')'},502);
  }
  if(p==='GitHub'){
   const r=await fetch('https://api.github.com/users/'+encodeURIComponent(u),{headers:{'User-Agent':'2kr-checker'}});
   if(r.status===404)return out({available:true});
   if(r.status===200){
    if(q.get('info')==='1'){const j=await r.json().catch(()=>({}));
     return out({available:false,info:{abonnes:j.followers,abonnements:j.following,depots:j.public_repos}})}
    return out({available:false});
   }
   return out({error:'GitHub '+r.status},r.status===403?429:502,r.status===403?{'Retry-After':'60'}:{});
  }
  if(p==='Roblox'){
   // API publique de Roblox : recherche par pseudo exact (aucune clé requise).
   const r=await fetch('https://users.roblox.com/v1/usernames/users',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({usernames:[u],excludeBannedUsers:false})});
   if(!r.ok)return out({error:'Roblox '+r.status},r.status===429?429:502,r.status===429?{'Retry-After':'30'}:{});
   const j=await r.json().catch(()=>({}));
   const hit=(j.data||[])[0];
   if(!hit)return out({available:true});
   if(q.get('info')!=='1')return out({available:false});
   const [fo,fw]=await Promise.all([
    fetch('https://friends.roblox.com/v1/users/'+hit.id+'/followers/count').then(x=>x.json()).catch(()=>({})),
    fetch('https://friends.roblox.com/v1/users/'+hit.id+'/followings/count').then(x=>x.json()).catch(()=>({}))
   ]);
   return out({available:false,info:{abonnes:fo.count,abonnements:fw.count}});
  }
  // Plateformes sans API publique : vérification « au mieux » en lisant la page publique du profil.
  // Le résultat est marqué approx:true (estimé) car ces plateformes peuvent changer ou bloquer.
  if(['Telegram','Twitter / X','Instagram','TikTok'].includes(p)){
   const UA={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36','Accept-Language':'en'};
   const est=a=>out({available:a,approx:true});
   const blocked=()=>out({error:p+' bloque la vérification automatique'},502);
   try{
    const e=encodeURIComponent(u);
    if(p==='Telegram'){
     const r=await fetch('https://t.me/'+e,{headers:UA});if(!r.ok)return blocked();
     const h=await r.text();
     return est(!(h.includes('tgme_page_extra')||!/<title>\s*Telegram: Contact @/i.test(h)));
    }
    if(p==='Twitter / X'){
     const r=await fetch('https://cdn.syndication.twimg.com/widgets/followbutton/info.json?screen_names='+e,{headers:UA});if(!r.ok)return blocked();
     const j=await r.json().catch(()=>null);if(!Array.isArray(j))return blocked();
     return est(j.length===0);
    }
    if(p==='Instagram'){
     const r=await fetch('https://www.instagram.com/'+e+'/',{headers:UA,redirect:'manual'});
     if(r.status===404)return est(true);if(r.status===200)return est(false);return blocked();
    }
    const r=await fetch('https://www.tiktok.com/@'+e,{headers:UA});
    if(r.status===404)return est(true);
    const h=await r.text();
    if(/"statusCode":10(221|202)/.test(h))return est(true);
    if(h.includes('"uniqueId":"'))return est(false);
    return blocked();
   }catch(err){return out({error:p+' injoignable'},502)}
  }
  return out({error:'plateforme non gérée par ce serveur'},501);
 }
};
