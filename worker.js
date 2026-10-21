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

export default {
 async fetch(req,env){
  if(req.method==='OPTIONS')return new Response(null,{headers:{...CORS,'Access-Control-Allow-Headers':'*'}});
  const url=new URL(req.url);
  const m=url.pathname.match(/^\/oauth\/(github|twitter|roblox)\/callback$/);
  if(m)return handleCallback(m[1],url,env);

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
   if(r.status===200)return out({available:false});
   return out({error:'GitHub '+r.status},r.status===403?429:502,r.status===403?{'Retry-After':'60'}:{});
  }
  return out({error:'plateforme non gérée par ce serveur'},501);
 }
};
