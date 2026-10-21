// Serveur de vérification (Cloudflare Workers, gratuit).
// Reçoit ?u=pseudo&p=plateforme et répond {"available":true|false}.
const CORS={'Access-Control-Allow-Origin':'*','Content-Type':'application/json'};
const out=(o,s=200,h={})=>new Response(JSON.stringify(o),{status:s,headers:{...CORS,...h}});

export default {
  async fetch(req){
    if(req.method==='OPTIONS')return new Response(null,{headers:{...CORS,'Access-Control-Allow-Headers':'*'}});
    const q=new URL(req.url).searchParams;
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
