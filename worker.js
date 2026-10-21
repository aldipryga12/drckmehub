if(typeof importScripts==='function')importScripts('core.js');
const api=typeof browser!=='undefined'?browser:chrome;
let busy=false;
let deviceKeyPromise;
function installationId(){if(!deviceKeyPromise)deviceKeyPromise=(async()=>{const saved=await api.storage.local.get('installationId');if(saved.installationId)return saved.installationId;const id=Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');await api.storage.local.set({installationId:id});return id;})().catch(e=>{deviceKeyPromise=null;throw e;});return deviceKeyPromise;}
function browserLabel(){const ua=navigator.userAgent;return /Firefox/i.test(ua)?'Firefox browser':/Edg\//.test(ua)?'Edge browser':'Chrome-compatible browser';}

async function request(base,path,body={},token=''){
 body={...body,device_id:await installationId(),device_label:browserLabel()};
 const r=await fetch(base+'/api/'+path,{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:'Bearer '+token}:{})},body:JSON.stringify(body),cache:'no-store',redirect:'error',signal:AbortSignal.timeout(20000)});
 const d=await r.json();if(!r.ok){const error=Error(d.error||'Server request failed.');error.status=r.status;throw error;}return d;
}
function validBase(raw){const u=new URL(raw);if(u.username||u.password||u.search||u.hash||u.pathname!=='/')throw Error('Enter the server origin only.');if(u.protocol!=='https:'&&!(u.protocol==='http:'&&['localhost','127.0.0.1'].includes(u.hostname)))throw Error('Use an HTTPS server URL.');return u.origin;}
function cookieURL(c){return 'https://'+c.domain.replace(/^\./,'')+c.path;}
async function remove(c){const d={url:cookieURL(c),name:c.name,storeId:c.storeId};if(c.partitionKey)d.partitionKey=c.partitionKey;if(c.firstPartyDomain)d.firstPartyDomain=c.firstPartyDomain;await api.cookies.remove(d);}
async function restore(c){const d={url:cookieURL(c),name:c.name,value:c.value,path:c.path,secure:c.secure,httpOnly:c.httpOnly,sameSite:c.sameSite,storeId:c.storeId};if(!c.hostOnly)d.domain=c.domain;if(!c.session)d.expirationDate=c.expirationDate;if(c.partitionKey)d.partitionKey=c.partitionKey;if(c.firstPartyDomain)d.firstPartyDomain=c.firstPartyDomain;return api.cookies.set(d);}
async function handle(m){
 if(m.type==='login'){
  const base=validBase(m.base);const d=await request(base,'login',{username:m.username,password:m.password});
  await api.storage.local.set({base,token:d.token,username:d.username});return {username:d.username};
 }
 if(m.type==='state'){const {base,token}=await api.storage.local.get(['base','token']);if(!token)return {loggedIn:false};try{const me=await request(base,'me',{},token);if(me.role!=='admin'&&!me.access?.device_bound){await api.storage.local.remove(['token','username']);return {loggedIn:false,notice:'Sign in once to register this browser and start your access plan.'};}return {base,...me,loggedIn:true};}catch(e){if(e.status===401){await api.storage.local.remove(['token','username']);return {loggedIn:false};}throw e;}}
 if(m.type==='logout'){const s=await api.storage.local.get(['base','token']);try{if(s.token)await request(s.base,'logout',{},s.token);}finally{await api.storage.local.remove(['token','username']);}return {};}
 if(m.type!=='start')throw Error('Unknown action.');
 if(busy)throw Error('Import already running.');busy=true;
 try{
  const s=await api.storage.local.get(['base','token']);if(!s.token)throw Error('Log in first.');
  const data=await request(s.base,'start',{},s.token);
  const rows=CookieImport.parse(JSON.stringify(data.cookies));
  for(const c of rows){if((c.domain||'chatgpt.com').replace(/^\./,'').toLowerCase()!=='chatgpt.com')throw Error('Server returned an unsupported cookie domain.');CookieImport.prepare(c,'https://chatgpt.com/','0');}
  let [tab]=await api.tabs.query({active:true,currentWindow:true});
  if(!tab||!tab.url||new URL(tab.url).hostname!=='chatgpt.com'){
   tab=await api.tabs.create({url:api.runtime.getURL('waiting.html'),active:true});
  }
  const stores=await api.cookies.getAllCookieStores();const store=stores.find(s=>s.tabIds.includes(tab.id));if(!store)throw Error('Cannot access this tab’s cookie storage.');
  const prepared=rows.map(c=>CookieImport.prepare(c,'https://chatgpt.com/',store.id));
  const existing=await api.cookies.getAll({domain:'chatgpt.com',storeId:store.id});
  let removed=0;
  try{
   for(const c of existing){await remove(c);removed++;}
   for(const d of prepared){const c=await api.cookies.set(d);if(!c)throw Error('Cookie rejected.');}
  }catch{
   let failed=false;
   try{for(const c of await api.cookies.getAll({domain:'chatgpt.com',storeId:store.id}))await remove(c);}catch{failed=true;}
   for(const c of existing){try{if(!await restore(c))failed=true;}catch{failed=true;}}
   throw Error(failed?'Import failed and some previous cookies could not be restored. Log in to ChatGPT again.':'Import failed. Previous cookies restored. Check the saved cookie export.');
  }
  await api.tabs.update(tab.id,{url:'https://chatgpt.com/'});
  return {message:`${prepared.length} cookies imported; ${removed} previous cookies removed.`};
 }finally{busy=false;}
}
api.runtime.onMessage.addListener((m,sender,sendResponse)=>{
 if(sender.id!==api.runtime.id||sender.tab){sendResponse({error:'Not allowed.'});return false;}
 handle(m).then(data=>sendResponse({ok:true,...data})).catch(e=>sendResponse({error:e.message || 'Could not complete the action.'}));return true;
});
