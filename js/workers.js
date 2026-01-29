const SECRET_KEY = "cuong.huynh";
const TOKEN_EXPIRE_HOURS = 24;

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        const method = request.method;
        const getAuth=(request)=>{let token=request.headers.get('Authorization')?.split(' ')[1];if(!token){const cookieHeader=request.headers.get('Cookie')|| "";const match=cookieHeader.match(/hpc_token=([^;]+)/);token=match ? match[1]:null}if(!token)return null;const verified=verifyToken(token,request);if(!verified)return null;return verified};
        if(url.pathname==='/login'){if(method==='GET'){const user=getAuth(request);if(user)return Response.redirect(`${url.origin}/`,302);return new Response(BaseLayout("Login",LoginContent,BotDetectScript,LoginScript,""),{headers:{"Content-Type":"text/html;charset=UTF-8"}})}if(method==='POST'){const{u,p}=await request.json();const inputHash=await hashPassword(p);const user=await env.DB.prepare("SELECT * FROM users WHERE username=?").bind(u).first();if(!user || user.password !==inputHash)return Response.json({error:"Incorrect account or password"},{status:401});const token=await generateToken(user,request);return Response.json({success:true,user:{username:user.username,role:user.role}},{headers:{"Set-Cookie":`hpc_token=${token};Path=/;Max-Age=86400;HttpOnly;SameSite=Lax;Secure`}})}}
        if(url.pathname==='/api/logout'){return Response.json({success:true},{headers:{"Set-Cookie":"hpc_token=;Path=/;HttpOnly;SameSite=Lax;Max-Age=0;Secure"}})}
        const user = getAuth(request);
        if(!user && url.pathname==='/'){return Response.redirect(`${url.origin}/login`,302)}
        const scripts = getScripts(url.pathname, user, user?.r || "");
        if(method==='GET' && url.pathname==='/'){return new Response(BaseLayout("Home",HomeContent,scripts.header,scripts.body,scripts.navTab),{headers:{"Content-Type":"text/html;charset=UTF-8"}})}
        if(method==='GET' && url.pathname==='/users'){return new Response(BaseLayout("Users",AdminUserContent,scripts.header,scripts.body,scripts.navTab),{headers:{"Content-Type":"text/html;charset=UTF-8"}})}
        if(method==='GET' && url.pathname==='/servers'){return new Response(BaseLayout("Servers",AdminServerContent,scripts.header,scripts.body,scripts.navTab),{headers:{"Content-Type":"text/html;charset=UTF-8"}})}
        if(method==='GET' && url.pathname==='/faq'){return new Response(BaseLayout("Users",FAQContent,scripts.header,scripts.body,scripts.navTab),{headers:{"Content-Type":"text/html;charset=UTF-8"}})}
        if(url.pathname==='/api/servers/verify'){if(!user)return Response.json({error:"Unauthorized"},{status:401});const{results:accounts}=await env.DB.prepare("SELECT * FROM accounts").all();const errors=[];for(const acc of accounts){try{const tokenData=await refreshGoogleToken(acc);if(!tokenData || tokenData.error)throw new Error("Google Error");await env.DB.prepare("UPDATE accounts SET status='active' WHERE id=?").bind(acc.id).run()}catch(e){errors.push(acc.name);await env.DB.prepare("UPDATE accounts SET status='error' WHERE id=?").bind(acc.id).run()}}return Response.json({success:true,errors})}
        if(method==='GET' && url.pathname==='/api/files'){if(!user)return Response.json({error:"Unauthorized"},{status:401});const urlParams=new URL(request.url).searchParams;const page=parseInt(urlParams.get('page')|| '1');const searchTerm=urlParams.get('q')|| "";const limit=30;const offset=(page - 1)* limit;let query,params;const searchPattern=`%${searchTerm}%`;if(user.r==='admin'){query=`SELECT * FROM files WHERE name LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?`;params=[searchPattern,limit,offset]}else{query=`SELECT * FROM files WHERE(status IN('public','internal')OR(status='private' AND owner=?))AND name LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?`;params=[user.u,searchPattern,limit,offset]}const{results}=await env.DB.prepare(query).bind(...params).all();return Response.json(results)}
        if(method==='POST'&&url.pathname==='/api/upload'){try{if(!user)return Response.json({error:"Unauthorized"},{status:401});const fileSize=parseInt(request.headers.get("content-length")||"0"),fileName=decodeURIComponent(request.headers.get("x-file-name")||"Untitled"),fileStatus=request.headers.get("x-file-status")||'private',rawContentType=request.headers.get("content-type")||'application/octet-stream';if(fileSize>104857600)return Response.json({error:"File too large"},{status:413});const userQuota=await env.DB.prepare("SELECT u.max_space,COALESCE(SUM(f.size),0)as used_space FROM users u LEFT JOIN files f ON u.username=f.owner WHERE u.username=? GROUP BY u.username").bind(user.u).first();if(userQuota&&userQuota.max_space!==-1&&(userQuota.used_space+fileSize>userQuota.max_space))return Response.json({error:"Storage quota exceeded"},{status:403});const{results:accounts}=await env.DB.prepare("SELECT * FROM accounts WHERE(total_space-used_space)>? AND status='active' ORDER BY(total_space-used_space)DESC LIMIT 3").bind(fileSize).all();if(!accounts||!accounts.length)return Response.json({error:"No storage available"},{status:507});const account=accounts[Math.floor(Math.random()*accounts.length)],accessToken=await refreshGoogleToken(account);if(!accessToken)throw new Error("Token refresh failed");const initRes=await fetch("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable",{method:'POST',headers:{'Authorization':'Bearer '+accessToken,'Content-Type':'application/json;charset=UTF-8','X-Upload-Content-Type':rawContentType},body:JSON.stringify({name:fileName,parents:[account.folder_id]})});const uploadUrl=initRes.headers.get('Location');if(!uploadUrl)throw new Error("G-Drive Init Failed");const googleRes=await fetch(uploadUrl,{method:'PUT',headers:{'Content-Length':fileSize.toString()},body:request.body});const driveData=await googleRes.json();if(driveData.id){try{await setPublic(driveData.id,accessToken)}catch(e){}await env.DB.batch([env.DB.prepare("INSERT INTO files(file_id,name,size,drive_file_id,account_id,owner,status)VALUES(?,?,?,?,?,?,?)").bind(crypto.randomUUID(),fileName,fileSize,driveData.id,account.id,user.u,fileStatus),env.DB.prepare("UPDATE accounts SET used_space=used_space+? WHERE id=?").bind(fileSize,account.id)]);return Response.json({success:true,fileId:driveData.id})}return Response.json({error:"Drive error",detail:driveData},{status:500})}catch(err){return Response.json({error:err.message},{status:500})}}
        if(method==='GET'&&url.pathname.startsWith('/api/proxy/')){const fileId=url.pathname.split('/').pop(),file=await env.DB.prepare("SELECT * FROM files WHERE file_id=?").bind(fileId).first();if(!file)return new Response("File not found",{status:404});const isPublic=file.status==='public',isInternal=file.status==='internal'&&user,isOwner=user&&(file.owner===user.u||user.r==='admin');if(!isPublic&&!isInternal&&!isOwner)return new Response("Access Denied",{status:403});const account=await env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(file.account_id).first(),accessToken=await refreshGoogleToken(account),driveRes=await fetch(`https://www.googleapis.com/drive/v3/files/${file.drive_file_id}?alt=media`,{headers:{Authorization:`Bearer ${accessToken}`}});if(!driveRes.ok)return new Response("G-Drive Error",{status:driveRes.status});const h=new Headers();['content-type','content-length','accept-ranges'].forEach(k=>{const v=driveRes.headers.get(k);if(v)h.set(k,v)});h.set('Content-Disposition',`${url.searchParams.has('download')?'attachment':'inline'}; filename="${encodeURIComponent(file.name)}"`);h.set('Cache-Control','public, max-age=3600');return new Response(driveRes.body,{status:driveRes.status,headers:h})}
        if(method==='DELETE'&&url.pathname.startsWith('/api/files/')){const fileId=url.pathname.split('/').pop(),file=await env.DB.prepare("SELECT * FROM files WHERE file_id=?").bind(fileId).first();if(!file)return Response.json({error:"File not found"},{status:404});if(user.r!=='admin'&&file.owner!==user.u)return Response.json({error:"No permission"},{status:403});const account=await env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(file.account_id).first(),token=await refreshGoogleToken(account),gdRes=await fetch(`https://www.googleapis.com/drive/v3/files/${file.drive_file_id}`,{method:'DELETE',headers:{Authorization:`Bearer ${token}`}});if(gdRes.status===204||gdRes.status===404){await env.DB.batch([env.DB.prepare("DELETE FROM files WHERE file_id=?").bind(fileId),env.DB.prepare("UPDATE accounts SET used_space=used_space-? WHERE id=?").bind(file.size,account.id)]);return Response.json({success:true})}return Response.json({error:"G-Drive delete failed"},{status:500})}
        if(url.pathname.startsWith('/api/servers')){if(!user)return Response.json({error:"Unauthorized"},{status:401});const accountId=url.pathname.split('/')[3];if(method==='GET'&&!accountId){const[a,f,u]=await Promise.all([env.DB.prepare("SELECT id,name,used_space,total_space FROM accounts").all(),env.DB.prepare("SELECT COUNT(*)as t FROM files").first(),env.DB.prepare("SELECT COUNT(*)as t FROM users").first()]);return Response.json({accounts:a.results,totalFiles:f?.t||0,totalUsers:u?.t||0})}if(user.r!=='admin')return Response.json({error:"Forbidden"},{status:403});if(method==='POST'){const d=await request.json();await env.DB.prepare("INSERT INTO accounts(id,name,client_id,client_secret,refresh_token,folder_id,used_space,total_space,status)VALUES(?,?,?,?,?,?,?,?, 'active')").bind(crypto.randomUUID(),d.name,d.client_id,d.client_secret,d.refresh_token,d.folder_id||'root',0,16106127360).run();return Response.json({success:true})}if(method==='DELETE'&&accountId){try{/*await env.DB.batch([env.DB.prepare("UPDATE files SET status='error' WHERE account_id=?").bind(accountId),env.DB.prepare("DELETE FROM accounts WHERE id=?").bind(accountId)]);*/return Response.json({success:true})}catch(e){return Response.json({error:e.message},{status:500})}}}
        if(url.pathname.startsWith('/api/users')){if(!user||user.r!=='admin')return Response.json({error:"Unauthorized"},{status:401});const targetUsername=url.pathname.split('/').pop(),isDetail=url.pathname!=='/api/users';if(method==='GET'){const{results:us}=await env.DB.prepare("SELECT u.username,u.role,u.max_space,u.created_at,COALESCE(SUM(f.size),0)as used_space FROM users u LEFT JOIN files f ON u.username=f.owner GROUP BY u.username").all();return Response.json(us)}if(method==='POST'&&!isDetail){const{u,p,r,m}=await request.json();if(!u||!p)return Response.json({error:"Lack of info"},{status:400});const lim=m!==undefined?parseInt(m):5368709120;const inputHash=await hashPassword(p);await env.DB.prepare("INSERT INTO users(username,password,role,max_space)VALUES(?,?,?,?)ON CONFLICT(username)DO UPDATE SET password=excluded.password,role=excluded.role,max_space=excluded.max_space").bind(u,inputHash,r||'user',lim).run();return Response.json({success:true})}if(isDetail){const target=decodeURIComponent(targetUsername);if(target==='administrator')return Response.json({error:"Forbidden Admin access"},{status:403});if(method==='PUT'){const d=await request.json(),up=[],pa=[];if(d.role){up.push("role=?");pa.push(d.role)}if(d.max_space!==undefined){up.push("max_space=?");pa.push(parseInt(d.max_space))}if(d.password&&d.password.trim()){up.push("password=?");const inputHash=await hashPassword(d.password);pa.push(inputHash)}if(up.length){pa.push(target);await env.DB.prepare(`UPDATE users SET ${up.join(",")} WHERE username=?`).bind(...pa).run()}return Response.json({success:true})}if(method==='DELETE'){if(target===user.u)return Response.json({error:"Self-delete denied"},{status:400});try{await env.DB.batch([env.DB.prepare("UPDATE files SET owner='unknown' WHERE owner=?").bind(target),env.DB.prepare("DELETE FROM users WHERE username=?").bind(target)]);return Response.json({success:true})}catch(e){return Response.json({error:e.message},{status:500})}}}}
        if(method==='POST'&&url.pathname==='/api/files/bulk-delete'){try{const{ids}=await request.json();if(!ids?.length)return Response.json({error:"No IDs"},{status:400});const q=`SELECT drive_file_id,account_id,size,owner FROM files WHERE file_id IN (${ids.map(()=>'?').join(',')})`,{results:fs}=await env.DB.prepare(q).bind(...ids).all();if(!fs.length)return Response.json({error:"No files"},{status:404});const validFs=fs.filter(f=>user.r==='admin'||f.owner===user.u);if(!validFs.length)return Response.json({error:"Forbidden"},{status:403});const accIds=[...new Set(validFs.map(f=>f.account_id))],tks={},szM={};for(const id of accIds){const a=await env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(id).first();if(a){tks[id]=await refreshGoogleToken(a);szM[id]=validFs.filter(f=>f.account_id===id).reduce((s,f)=>s+(f.size||0),0)}}await Promise.all(validFs.map(async f=>{const t=tks[f.account_id];if(!t)return;try{const r=await fetch(`https://www.googleapis.com/drive/v3/files/${f.drive_file_id}`,{method:'DELETE',headers:{Authorization:'Bearer '+t}});return r.ok||r.status===404}catch(e){}}));const stmts=ids.map(id=>env.DB.prepare("DELETE FROM files WHERE file_id=?").bind(id));Object.keys(szM).forEach(id=>stmts.push(env.DB.prepare("UPDATE accounts SET used_space=MAX(0,used_space-?) WHERE id=?").bind(szM[id],id)));await env.DB.batch(stmts);return Response.json({success:true,count:validFs.length})}catch(e){return Response.json({error:e.message},{status:500})}}
        if(method==='GET'&&url.pathname.startsWith('/api/thumbnail/')){const id=url.pathname.split('/').pop(),f=await env.DB.prepare("SELECT drive_file_id,account_id FROM files WHERE file_id=?").bind(id).first();if(!f||!f.drive_file_id)return new Response("Not Found",{status:404});const a=await env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(f.account_id).first();if(!a)return new Response("Account Not Found",{status:404});try{const tk=await refreshGoogleToken(a),meta=await fetch(`https://www.googleapis.com/drive/v3/files/${f.drive_file_id}?fields=thumbnailLink`,{headers:{Authorization:'Bearer '+tk}});if(!meta.ok)return new Response("Meta Error",{status:meta.status});const{thumbnailLink:link}=await meta.json();if(!link)return new Response("No thumb",{status:404});const img=await fetch(link);return new Response(img.body,{headers:{'Content-Type':'image/jpeg','Cache-Control':'public, max-age=604800','Access-Control-Allow-Origin':'*'}})}catch(e){return new Response("Error",{status:500})}}
        if(url.pathname.startsWith('/api/raw/')){const id=url.pathname.split('/').pop(),tk=url.searchParams.get('token'),ex=url.searchParams.get('expires');if(!tk||!ex)return new Response("Missing params",{status:400});if(Date.now()>parseInt(ex))return new Response("Expired",{status:403});try{const f=await env.DB.prepare("SELECT drive_file_id,account_id FROM files WHERE file_id=?").bind(id).first();if(!f)return new Response("Not found",{status:404});const a=await env.DB.prepare("SELECT * FROM accounts WHERE id=?").bind(f.account_id).first(),atk=await refreshGoogleToken(a),dr=await fetch(`https://www.googleapis.com/drive/v3/files/${f.drive_file_id}?alt=media`,{headers:{Authorization:'Bearer '+atk}});if(!dr.ok)return new Response("Drive error",{status:dr.status});const h=new Headers(dr.headers);h.set('Access-Control-Allow-Origin','*');h.set('Content-Disposition','inline');h.set('Cache-Control','public, max-age=3600');return new Response(dr.body,{status:dr.status,headers:h})}catch(e){return new Response(e.message,{status:500})}}
        return new Response("Not Found", { status: 404 });
    }
};

// Extend Script
async function generateToken(u,r){const ua=btoa(r.headers.get('user-agent')||''),exp=Date.now()+TOKEN_EXPIRE_HOURS*36e5,p={u:u.username,r:u.role,ua:ua,exp:exp},d=btoa(JSON.stringify(p)),s=btoa(p.u+SECRET_KEY+exp);return`${d}.${s}`}
function verifyToken(t,r){try{if(!t)return null;const[d,s]=t.split('.'),p=JSON.parse(atob(d));if(s!==btoa(p.u+SECRET_KEY+p.exp)||Date.now()>p.exp)return null;if(p.ua!==btoa(r.headers.get('user-agent')||''))return null;return p}catch(e){return null}}
async function hashPassword(p){const d=new TextEncoder().encode(p+SECRET_KEY),b=await crypto.subtle.digest('SHA-256',d);return Array.from(new Uint8Array(b)).map(b=>b.toString(16).padStart(2,'0')).join('')}
async function refreshGoogleToken(a){const r=await fetch('https://oauth2.googleapis.com/token',{method:'POST',body:JSON.stringify({client_id:a.client_id,client_secret:a.client_secret,refresh_token:a.refresh_token,grant_type:'refresh_token'})});return(await r.json()).access_token}
async function setPublic(id,t){await fetch(`https://www.googleapis.com/drive/v3/files/${id}/permissions`,{method:'POST',headers:{Authorization:'Bearer '+t,'Content-Type':'application/json'},body:JSON.stringify({role:'reader',type:'anyone'})})}

// HTML Control
function getScripts(path,user,role){let h=BotDetectScript,b="",n=`<a href="/" class="py-5 text-slate-400 text-[11px] font-bold uppercase tracking-widest transition-all hover:text-indigo-600"><i class="fas fa-folder mr-1"></i>Files</a>`;if(role==='admin'){n+=`<a href="/servers" class="py-5 text-slate-400 text-[11px] font-bold uppercase tracking-widest transition-all hover:text-indigo-600"><i class="fas fa-server mr-1"></i>Servers</a><a href="/users" class="py-5 text-slate-400 text-[11px] font-bold uppercase tracking-widest transition-all hover:text-indigo-600"><i class="fas fa-users-gear mr-1"></i>Users</a><a href="/faq" class="py-5 text-slate-400 text-[11px] font-bold uppercase tracking-widest transition-all hover:text-indigo-600"><i class="fa-solid fa-circle-question mr-1"></i>FAQ</a>`}switch(path){case'/':b=HomeScript;break;case'/login':b=LoginScript;break;case'/users':b=(role==='admin')?AdminUserScript:"";break;case'/servers':b=(role==='admin')?AdminServerScript:"";break}return{header:h,body:b,navTab:n}}

const logo = 'data:image/WEBP;base64,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';
    
function BaseLayout(title, content, headerScript = "", bodyScript = "", navTab = "") {
    return `
        <!DOCTYPE html>
        <html lang="vi" class="dark">

        <head>
            <meta charset="UTF-8">
            <title>${title} - Data Management System</title>
            <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
            <meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">
            <meta http-equiv="x-ua-compatible" content="ie=edge">
            <link rel="icon" href="https://cdn.jsdelivr.net/gh/phucuong13029x/phucuongds-static@main/img/favicon.ico" type="image/x-icon">
            ${headerScript}
            <style>@import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;600;800&family=JetBrains+Mono&display=swap');body{font-family:'Plus Jakarta Sans',sans-serif;background:#fbfcfe;overflow-x:hidden}::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#cbd5e1;border-radius:10px}.btn-toggle-active{background-color:#6366f1 !important;color:white !important;box-shadow:0 4px 12px rgba(99,102,241,0.3)}.tab-active{color:#6366f1;border-bottom:3px solid #6366f1}.preview-modal{background:rgba(10,15,30,0.95);backdrop-filter:blur(15px)}.text-preview-container{background:#0d1117;border-radius:1.5rem;width:100%;max-width:1100px;height:85vh;display:flex;flex-direction:column;overflow:hidden;border:1px solid rgba(255,255,255,0.1);position:relative}.text-preview-header{padding:1.25rem 1.5rem;border-bottom:1px solid rgba(255,255,255,0.1);display:flex;align-items:center;justify-content:space-between;background:#161b22;z-index:10}.text-preview-body{padding:1.5rem;overflow-y:auto;flex:1;position:relative}.code-block{font-family:'JetBrains Mono',monospace;color:#e2e8f0;font-size:13px;line-height:1.7;text-align:left};.img-container{background:#e0e0e0;position:relative;overflow:hidden}.img-container::before{content:"";position:absolute;top:0;left:-100%;width:100%;height:100%;background:linear-gradient(90deg,transparent,rgba(255,255,255,0.3),transparent);animation:skeleton-loading 1.2s infinite;z-index:1}.img-container.loaded::before{animation:none;display:none}.lazy-img{transition:opacity 0.5s ease-in-out,filter 0.5s ease-out;filter:blur(8px);opacity:0;z-index:2}@keyframes skeleton-loading{100%{left:100%}}select option{padding:12px;font-size:14px}.custom-scrollbar::-webkit-scrollbar{width:4px}.custom-scrollbar::-webkit-scrollbar-track{background:rgba(255,255,255,0.05)}.custom-scrollbar::-webkit-scrollbar-thumb{background:rgba(59,130,246,0.5);border-radius:10px}.toast-item{animation:slideIn 0.3s ease forwards}@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}.toast-fade-out{animation:fadeOut 0.5s ease forwards}@keyframes fadeOut{to{transform:translateY(-20px);opacity:0}}@keyframes pulse-ring{0%{transform:scale(0.8);opacity:0.5}100%{transform:scale(1.3);opacity:0}}.upload-pulse::before{content:'';position:absolute;width:100%;height:100%;background-color:inherit;border-radius:50%;z-index:-1;animation:pulse-ring 2s cubic-bezier(0.455,0.03,0.515,0.955) infinite}</style>
            <script src="https://cdn.tailwindcss.com"></script>
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        </head>

        <body id="__next" class="text-slate-800 bg-white dark:bg-gray-950 dark:text-slate-200 transition-colors duration-300" style="display:none; visibility:hidden">
            <nav class="bg-white/80 dark:bg-slate-950/80 dark:border-slate-800 backdrop-blur-md border-b px-8 flex justify-between items-center sticky top-0 z-50 h-16 shadow-sm shadow-indigo-200">
                <div class="flex items-center gap-10 h-full">
                    <div class="text-indigo-600 font-black text-xl cursor-pointer" onclick="location.reload()">
                        <img class="w-auto h-8" src="${logo}" />
                    </div>
                    <div class="flex gap-8 h-full items-center">
                        ${navTab}
                    </div>
                </div>
                <div id="navRight">
                </div>
            </nav>

            <main class="max-w-8xl m-auto p-6">
                ${content}
            </main>

            <div id="confirmModal" class="hidden fixed inset-0 z-[100] flex items-center justify-center p-4">
                <div class="absolute inset-0 bg-slate-900/60 backdrop-blur-sm"></div>
                <div
                    class="relative dark:bg-slate-900 rounded-3xl shadow-2xl max-w-sm w-full p-6 transform transition-all scale-100">
                    <div class="flex flex-col items-center text-center">
                        <div class="w-16 h-16 bg-rose-50 text-rose-500 rounded-2xl flex items-center justify-center mb-4"><i class="fas fa-trash-alt text-2xl"></i></div>
                        <h3 class="text-lg font-bold dark:text-slate-200 mb-2">Confirm deletion</h3>
                        <p id="confirmMessage" class="text-slate-500 text-sm mb-6">Are you sure you want to delete the selected files? This action cannot be undone.</p>
                        <div class="flex gap-3 w-full">
                            <button onclick="closeConfirmModal()" class="flex-1 py-3 px-4 rounded-xl bg-slate-100 text-slate-600 font-bold text-xs hover:bg-slate-200 transition-all">CANCEL</button>
                            <button id="confirmExecuteBtn" class="flex-1 py-3 px-4 rounded-xl bg-rose-500 text-white font-bold text-xs hover:bg-rose-600 transition-all">DELETE NOW</button>
                        </div>
                    </div>
                </div>
            </div>

            <div id="toastContainer" class="fixed bottom-5 right-5 z-[200] flex flex-col gap-3"></div>

            <footer class="text-[11px] text-center p-6 text-slate-500 mt-auto border-t border-slate-100 dark:border-slate-800">
                &copy; 2026 - Bản quyền thuộc 
                <a href="https://phucuongds.vercel.app" class="text-blue-500 hover:text-blue-600 font-medium transition-colors">phucuongds</a>
            </footer>

            <script>
                let currentView = localStorage.getItem('viewMode') || 'list';
                
                function formatSize(bytes) {
                    if (bytes === 0) return '0 B';
                    const k = 1024;
                    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
                };

                /**
                @param {string} type - Loại: 'success' | 'error' | 'info'
                @param {string} message - Nội dung thông báo
                @param {number} duration - Thời gian hiển thị (ms), mặc định 2000ms
                */
                function showAlert(type, message, duration = 2000) {
                    let container = document.getElementById('alert-container');
                    if (!container) {
                        container = document.createElement('div');
                        container.id = 'alert-container';
                        container.className = 'fixed top-4 right-4 z-[9999] flex flex-col gap-3 pointer-events-none';
                        document.body.appendChild(container);
                    }
                    const configs = {
                        success: { bg: 'bg-emerald-500', icon: 'fa-check-circle' },
                        error: { bg: 'bg-rose-500', icon: 'fa-exclamation-triangle' },
                        info: { bg: 'bg-indigo-500', icon: 'fa-info-circle' }
                    };
                    const config = configs[type] || configs.info;
                    const alert = document.createElement('div');
                    alert.className = \`flex items-center gap-3 px-4 py-3 rounded-2xl text-white shadow-2xl transform translate-x-full opacity-0 transition-all duration-500 ease-out pointer-events-auto min-w-[280px] \${config.bg}\`;
                    alert.innerHTML = \`
                        <i class="fas \${config.icon} text-lg"></i>
                        <div class="flex-1">
                            <p class="text-xs font-bold uppercase tracking-wider opacity-80">\${type}</p>
                            <p class="text-sm font-medium">\${message}</p>
                        </div>
                        <button class="ml-2 hover:opacity-70 transition-opacity" onclick="this.parentElement.remove()"><i class="fas fa-times text-xs"></i></button>
                    \`;
                    container.appendChild(alert);
                    setTimeout(() => {
                        alert.classList.remove('translate-x-full', 'opacity-0');
                    }, 10);

                    setTimeout(() => {
                        alert.classList.add('translate-x-full', 'opacity-0');
                        setTimeout(() => alert.remove(), 500);
                    }, duration);
                };
                function showConfirmModal(message, callback) {
                    const modal = document.getElementById('confirmModal');
                    const msgLabel = document.getElementById('confirmMessage');
                    const executeBtn = document.getElementById('confirmExecuteBtn');
                    msgLabel.innerText = message;
                    modal.classList.remove('hidden');
                    executeBtn.onclick = async () => {
                        await callback();
                        closeConfirmModal();
                    };
                };
        
                function closeConfirmModal() {
                    document.getElementById('confirmModal').classList.add('hidden');
                };

                async function logout() {
                    const _0x4f21 = [
                        '\x2f\x61\x70\x69\x2f\x6c\x6f\x67\x6f\x75\x74',
                        '\x69\x6e\x63\x6c\x75\x64\x65',                
                        '\x6c\x6f\x67',                          
                        '\x63\x6c\x65\x61\x72',               
                        '\x2f\x6c\x6f\x67\x69\x6e'             
                    ];
                    try {
                        await fetch(_0x4f21[0], { 
                            credentials: _0x4f21[1] 
                        });
                    } catch (_0x1e2e) {
                    }
                    localStorage[_0x4f21[3]]();
                    window.location.href = _0x4f21[4];
                }

                const updateAuthUI=()=>{const _0x5f=['\x6e\x61\x76\x52\x69\x67\x68\x74','\x67\x65\x74\x49\x74\x65\x6d','\x68\x70\x63\x5f\x75\x73\x65\x72','\x68\x70\x63\x5f\x72\x6f\x6c\x65','\x69\x6e\x6e\x65\x72\x48\x54\x4d\x4c'];const n=document.getElementById(_0x5f[0]),u=localStorage[_0x5f[1]](_0x5f[2]),r=localStorage[_0x5f[1]](_0x5f[3]);if(u&&r){n[_0x5f[4]]=\`<div class="flex items-center gap-3"><div class="text-right hidden sm:block"><p class="text-[10px] font-extrabold dark:text-slate-200 uppercase">\${u}</p><p class="text-[9px] text-indigo-500 font-bold">\${r.toUpperCase()}</p></div><button onclick="logout()" class="w-11 h-11 bg-slate-100 dark:bg-slate-900 rounded-xl flex items-center justify-center text-slate-500 hover:text-rose-500 transition-all"><i class="fas fa-power-off"></i></button></div>\`}else{n[_0x5f[4]]=\`<a href="/login" class="bg-indigo-600 text-white px-7 py-3 rounded-xl text-[10px] font-bold uppercase shadow-lg shadow-indigo-600/20 hover:scale-105 transition-all">Log in</a>\`}};
                updateAuthUI();

                const showToast=(_0x1,_0x2='info',_0x3=3000)=>{const _0x4=['\x74\x6f\x61\x73\x74\x43\x6f\x6e\x74\x61\x69\x6e\x65\x72','\x64\x69\x76','\x62\x67\x2d\x67\x72\x65\x65\x6e\x2d\x35\x30\x30','\x62\x67\x2d\x72\x65\x64\x2d\x35\x30\x30','\x62\x67\x2d\x62\x6c\x75\x65\x2d\x35\x30\x30','\x62\x67\x2d\x79\x65\x6c\x6c\x6f\x77\x2d\x35\x30\x30','\x63\x6c\x61\x73\x73\x4e\x61\x6d\x65','\x74\x6f\x61\x73\x74\x2d\x69\x74\x65\x6d\x20','\x20\x74\x65\x78\x74\x2d\x77\x68\x69\x74\x65\x20\x70\x78\x2d\x36\x20\x70\x79\x2d\x33\x20\x72\x6f\x75\x6e\x64\x65\x64\x2d\x32\x78\x6c\x20\x73\x68\x61\x64\x6f\x77\x2d\x32\x78\x6c\x20\x66\x6c\x65\x78\x20\x69\x74\x65\x6d\x73\x2d\x63\x65\x6e\x74\x65\x72\x20\x67\x61\x70\x2d\x33\x20\x6d\x69\x6e\x2d\x77\x2d\x5b\x32\x35\x30\x70\x78\x5d','\x69\x6e\x6e\x65\x72\x48\x54\x4d\x4c','\x74\x6f\x61\x73\x74\x2d\x66\x61\x64\x65\x2d\x6f\x75\x74'];const c=document.getElementById(_0x4[0]),t=document.createElement(_0x4[1]),cl={success:_0x4[2],error:_0x4[3],info:_0x4[4],warning:_0x4[5]};t[_0x4[6]]=_0x4[7]+(cl[_0x2]||cl.info)+_0x4[8];t[_0x4[9]]=\`<span class="font-medium text-sm">\${_0x1}</span><button onclick="this.parentElement.remove()" class="ml-auto opacity-70 hover:opacity-100">&times;</button>\`;c.appendChild(t);setTimeout(()=>{t.classList.add(_0x4[10]);setTimeout(()=>t.remove(),500)},_0x3);return t};

                const dateFormatString = (e) => {
                    if (!e) return "";
                    const dateObj = new Date(e.endsWith('Z') ? e : e.replace(' ', 'T') + 'Z');
                    return dateObj.toLocaleString('vi-VN', {
                        timeZone: 'Asia/Ho_Chi_Minh',
                        day: '2-digit',
                        month: '2-digit',
                        year: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                        hourCycle: 'h23' 
                    }).replace(/,/g, ''); 
                }
                window.api=async(_0x1a,_0x3b={})=>{const _0x5c=['\x46\x6f\x72\x6d\x44\x61\x74\x61','\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x79\x70\x65','\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6a\x73\x6f\x6e','\x69\x6e\x63\x6c\x75\x64\x65','\x65\x72\x72\x6f\x72','\x53\x65\x73\x73\x69\x6f\x6e\x20\x68\x61\x73\x20\x65\x78\x70\x69\x72\x65\x64\x21','\x53\x65\x73\x73\x69\x6f\x6e\x20\x65\x78\x70\x69\x72\x65\x64'];const h={..._0x3b.headers};if(!(_0x3b.body instanceof window[_0x5c[0]])){h[_0x5c[1]]=_0x5c[2]}try{const r=await fetch(_0x1a,{..._0x3b,headers:h,credentials:_0x5c[3]});if(r.status===401){if(typeof showAlert==='\x66\x75\x6e\x63\x74\x69\x6f\x6e')showAlert(_0x5c[4],_0x5c[5]);if(typeof logout==='\x66\x75\x6e\x63\x74\x69\x6f\x6e')logout();throw new Error(_0x5c[6])}return r}catch(e){throw e}};
                (function(){const _0x5c=['\x68\x74\x74\x70\x73\x3a\x2f\x2f\x70\x68\x75\x63\x75\x6f\x6e\x67\x64\x73\x2e\x76\x65\x72\x63\x65\x6c\x2e\x61\x70\x70','\x70\x68\x75\x63\x75\x6f\x6e\x67\x64\x73','\x66\x6f\x6f\x74\x65\x72','\x61\x5b\x68\x72\x65\x66\x2a\x3d\x22\x70\x68\x75\x63\x75\x6f\x6e\x67\x64\x73\x22\x5d','\x67\x65\x74\x43\x6f\x6d\x70\x75\x74\x65\x64\x53\x74\x79\x6c\x65','\x64\x69\x73\x70\x6c\x61\x79','\x6e\x6f\x6e\x65','\x76\x69\x73\x69\x62\x69\x6c\x69\x74\x79','\x68\x69\x64\x64\x65\x6e','\x6f\x70\x61\x63\x69\x74\x79','\x30','\x6c\x6f\x63\x61\x74\x69\x6f\x6e','\x68\x72\x65\x66','\x72\x65\x70\x6c\x61\x63\x65'];let _0x2a=false;const _0x4b=()=>{if(_0x2a||window[_0x5c[11]][_0x5c[12]].includes(_0x5c[1]))return;const f=document.querySelector(_0x5c[2]),l=f?f.querySelector(_0x5c[3]):null;const s=f?window[_0x5c[4]](f):{};const h=f&&(s[_0x5c[5]]===_0x5c[6]||s[_0x5c[7]]===_0x5c[8]||s[_0x5c[9]]===_0x5c[10]||f.offsetHeight===0);if(!f||!l||l.textContent.trim().toLowerCase()!==_0x5c[1]||h){_0x2a=true;window[_0x5c[11]][_0x5c[13]](_0x5c[0])}};setTimeout(()=>{_0x4b();const o=new MutationObserver(_0x4b);o.observe(document.body,{childList:true,subtree:true,attributes:true,characterData:true})},3000)})();
                async function loadData(){try{const _0x1a=['\x2f\x61\x70\x69\x2f\x73\x65\x72\x76\x65\x72\x73','\x74\x6f\x74\x61\x6c\x55\x73\x65\x64','\x70\x6f\x6f\x6c\x42\x61\x72','\x73\x74\x61\x74\x46\x69\x6c\x65\x73','\x73\x74\x61\x74\x55\x73\x65\x72\x73','\x61\x63\x63\x6f\x75\x6e\x74\x4c\x69\x73\x74','\x65\x72\x72\x6f\x72'];const res=await api(_0x1a[0]),data=await res.json(),accs=data.accounts||[];const u=accs.reduce((a,b)=>a+(b.used_space||0),0),l=accs.reduce((a,b)=>a+(b.total_space||0),0);const eU=document.getElementById(_0x1a[1]);if(eU)eU.innerHTML=\`\${formatSize(u)} / <span class="text-xs opacity-50">\${formatSize(l)}</span>\`;const pB=document.getElementById(_0x1a[2]);if(pB)pB.style.width=(u/l*100)+'%';const sF=document.getElementById(_0x1a[3]);if(sF)sF.innerText=(data.totalFiles||0).toLocaleString();const sU=document.getElementById(_0x1a[4]);if(sU)sU.innerText=(data.totalUsers||0).toLocaleString();const lst=document.getElementById(_0x1a[5]);if(!lst)return;if(accs.length===0){lst.innerHTML='<div class="col-span-full text-center p-10 text-slate-500 italic">No storage accounts connected.</div>';return}lst.innerHTML=accs.map(acc=>{const pct=((acc.used_space/acc.total_space)*100).toFixed(2),isE=acc.status===_0x1a[6];const c1=isE?'border-red-500/40':'border-white/5',c2=isE?'bg-red-500/20 text-red-500':'bg-gradient-to-tr from-indigo-500 to-purple-500 text-white',c3=isE?'text-red-400':'text-indigo-100',c4=isE?'text-red-400':'text-indigo-400',c5=isE?'bg-red-500':'bg-gradient-to-r from-indigo-500 to-purple-500';return\`<div class="group relative bg-[#0f172a]/60 backdrop-blur-xl p-5 rounded-[2rem] border \${c1} hover:border-indigo-500/40 transition-all duration-500 shadow-xl"><button onclick="confirmDeleteAccount('\${acc.id}','\${acc.name}')" class="absolute top-4 right-4 p-2.5 rounded-xl bg-red-500/10 text-red-500 opacity-0 group-hover:opacity-100 transition-all duration-300 hover:bg-red-500 hover:text-white z-10"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg></button><div class="flex items-center gap-3 mb-5"><div class="w-10 h-10 rounded-2xl \${c2} flex items-center justify-center shadow-lg">\${isE?'ERR':'SVG'}</div><div class="pr-8"><h4 class="font-bold text-sm \${c3} tracking-tight truncate">\${acc.name}</h4><p class="text-[9px] text-slate-500 font-mono italic">ID: \${acc.id.slice(0,12)}</p></div></div><div class="space-y-2"><div class="flex justify-between text-[10px] font-black \${c4} uppercase"><span>Capacity</span><span>\${isE?'ERROR':pct+'%'}</span></div><div class="w-full bg-white/5 h-1.5 rounded-full overflow-hidden"><div class="\${c5} h-full transition-all duration-1000" style="width:\${pct}%"></div></div><div class="flex justify-between text-[9px] font-bold text-slate-500 uppercase"><span>\${formatSize(acc.used_space)}</span><span>\${formatSize(acc.total_space)}</span></div></div></div>\`}).join('')}catch(e){console.error(e)}}
            </script>
            ${bodyScript}
        </body> 

        </html>
    `;
}

const BotDetectScript = `
<!--<script disable-devtool-auto src="https://cdn.jsdelivr.net/npm/disable-devtool" clear-log='true' disable-select='true' disable-copy='true' disable-cut='true' disable-paste='true'></script>-->
    <script type="module">
        (function(_0x1a2b, _0x3c4d) {
            const _0x5e6f = {
                'a': 'loading',
                'b': 'botDetectionResult',
                'c': 'https://openfpcdn.io/botd/v2',
                'd': 'bot',
                'e': 'botProbability',
                'f': 'unknown',
                'g': 'done',
                'h': 'Bot detection complete:',
                'i': 'BotD error:'
            };

            window[_0x5e6f.b] = { [_0x5e6f.a]: !![] };

            async function _0x9876() {
                try {
                    const _0x1111 = import(_0x5e6f.c);
                    const _0x2222 = await _0x1111;
                    const _0x3333 = await _0x2222['load']();
                    const _0x4444 = await _0x3333['detect']();

                    window[_0x5e6f.b] = {
                        'isBot': _0x4444[_0x5e6f.d],
                        'confidence': _0x4444[_0x5e6f.e] || _0x5e6f.f,
                        [_0x5e6f.g]: !![]
                    };
                    console['log'](_0x5e6f.h, window[_0x5e6f.b]);
                } catch (_0x5555) {
                    console['error'](_0x5e6f.i, _0x5555);
                    window[_0x5e6f.b] = { 'isBot': ![], [_0x5e6f.g]: !![], 'error': !![] };
                }
            }
            _0x9876();
        })();
    </script>
    <script type="text/javascript">
        (function(_0x1b2c, _0x3d4e) {
            const _0x5f6a = {
                'a': 'botDetectionResult',
                'b': 'done',
                'c': 'isBot',
                'd': 'DOMContentLoaded',
                'e': '__next',
                'f': 'block',
                'g': 'visible',
                'h': '\x42\x6f\x74\x20\x64\x65\x74\x65\x63\x74\x65\x64\x21\x20\x41\x63\x63\x65\x73\x73\x20\x64\x65\x6e\x69\x65\x64\x2e' // "Bot detected! Access denied."
            };

            function _0x22ab(_0x44cc, _0x12ff = 0x1388) {
                const _0x33dd = Date.now();
                const _0x55ee = setInterval(() => {
                    const _0xres = window[_0x5f6a.a];
                    if (_0xres && _0xres[_0x5f6a.b]) {
                        clearInterval(_0x55ee);
                        _0x44cc(_0xres);
                    } else if (Date.now() - _0x33dd > _0x12ff) {
                        clearInterval(_0x55ee);
                        _0x44cc({ [_0x5f6a.c]: ![], 'timeout': !![] });
                    }
                }, 0x64);
            }

            document.addEventListener(_0x5f6a.d, () => {
                _0x22ab((_0x0011) => {
                    const _0xdom = document.getElementById(_0x5f6a.e);
                    if (!_0xdom) return;

                    if (_0x0011[_0x5f6a.c]) {
                        _0xdom.innerHTML = '<h2>' + _0x5f6a.h + '</h2>';
                        return;
                    }
                    _0xdom.style.display = _0x5f6a.f;
                    _0xdom.style.visibility = _0x5f6a.g;
                });
            });
        })();
    </script>
`;

const LoginContent = `
    <section class="page-content active min-h-[70vh] flex items-center justify-center"><div class="dark:bg-slate-900 p-12 rounded-[3.5rem] w-full max-w-md text-center shadow-2xl border border-white/5"><h3 class="text-2xl font-extrabold mb-8 dark:text-slate-200 uppercase tracking-tight">Management system</h3><input id="u" type="text" placeholder="Username" class="w-full px-4 py-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all" autocomplete="off"> <input id="p" type="password" placeholder="Password" class="w-full px-4 py-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 text-slate-700 dark:text-slate-200 focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 outline-none transition-all mt-4 mb-10"><button onclick="handleLogin()" class="w-full bg-indigo-600 hover:bg-indigo-500 text-white p-5 rounded-2xl font-bold uppercase text-xs shadow-xl shadow-indigo-600/40 transition-all active:scale-[0.98]">Login</button></div></section>
`;

const LoginScript = `
    <script>
        const handleLogin=async()=>{const _0x2=['\x75','\x70','\x2f\x6c\x6f\x67\x69\x6e','\x50\x4f\x53\x54','\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x79\x70\x65','\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6a\x73\x6f\x6e','\x68\x70\x63\x5f\x74\x6f\x6b\x65\x6e','\x68\x70\x63\x5f\x75\x73\x65\x72','\x68\x70\x63\x5f\x72\x6f\x6c\x65','\x2f','\x65\x72\x72\x6f\x72','\x53\x61\x69\x20\x74\x20\x6b\x68\x6f\x1e\x6e\x20\x68\x6f\x1eb\x63\x20\x6d\x1ead\x74\x20\x6b\x68\x1ea\x75','\x53\x65\x72\x76\x65\x72\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x20\x65\x72\x72\x6f\x72'];const u=document.getElementById(_0x2[0]).value,p=document.getElementById(_0x2[1]).value;try{const r=await fetch(_0x2[2],{method:_0x2[3],headers:{[_0x2[4]]:_0x2[5]},body:JSON.stringify({u,p})});if(r.ok){const d=await r.json();localStorage.setItem(_0x2[6],d.token);localStorage.setItem(_0x2[7],d.user.username);localStorage.setItem(_0x2[8],d.user.role);setTimeout(()=>window.location.replace(_0x2[9]),1000)}else{const d=await r.json();showAlert(_0x2[10],d.error||_0x2[11])}}catch(e){showAlert(_0x2[10],_0x2[12])}};
    </script>
`;

const HomeContent = `
    <section class="page-content space-y-8"><div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-3 gap-4 mb-8"><div class="bg-gradient-to-br from-indigo-600 to-violet-700 p-3 rounded-2xl text-white shadow-lg"><p class="text-indigo-100 text-[12px] uppercase font-bold">Capacity</p><div class="flex items-baseline gap-2"><h3 id="totalUsed" class="text-xl font-black mt-1">0</h3></div><div class="w-full bg-slate-100 h-1.5 mt-2 rounded-full overflow-hidden"><div id="poolBar" class="bg-indigo-500 h-full transition-all duration-500" style="width:0%"></div></div></div><div class="bg-gradient-to-br from-indigo-600 to-violet-700 p-3 rounded-2xl text-white shadow-lg"><p class="text-indigo-100 text-[12px] uppercase font-bold">Total number of files</p><h3 id="statFiles" class="text-xl font-black mt-1">0</h3></div><div class="bg-gradient-to-br from-indigo-600 to-violet-700 p-3 rounded-2xl text-white shadow-lg"><p class="text-indigo-100 text-[12px] uppercase font-bold">Member</p><h3 id="statUsers" class="text-xl font-black mt-1">0</h3></div></div><div class="bg-white dark:bg-slate-900 border dark:border-slate-800 rounded-[2.5rem] p-10"><div class="flex justify-between items-center mb-3"><h2 class="text-md font-extrabold uppercase">File list</h2><button id="bulkActions" onclick="deleteSelectedFiles()" class="hidden bg-red-600/20 hover:bg-red-600 text-red-500 hover:text-white px-5 py-2 rounded-xl text-[10px] font-bold uppercase">Delete (<span id="selectedCount" class="text-gray-400"></span>) file</button></div><div class="flex justify-between items-center mb-3"><div class="relative"><span class="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-500"><svg class="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></span><input type="text" id="searchInput" placeholder="Search for files..." class="w-full h-10 pl-10 bg-white dark:bg-slate-900 dark:border-slate-800 border px-5 py-2.5 rounded-xl text-[11px] flex-1 outline-none shadow-sm focus:ring-2 focus:ring-indigo-500" autocomplete="off"></div><div class="flex items-center gap-2 bg-gray-800/50 p-1 rounded-xl border border-white/5"><button onclick='changeView("list")' id="btnList" class="p-2 rounded-lg transition-all bg-blue-600 text-white shadow-lg"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><button onclick='changeView("grid")' id="btnGrid" class="p-2 rounded-lg transition-all text-gray-400 hover:bg-white/5"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 5a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1V5zm10 0a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1V5zM4 15a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1H5a1 1 0 01-1-1v-4zm10 0a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z"/></svg></button></div></div><div id="fileContainer" class=""></div></div><div class="mt-6 text-center"><button id="btnLoadMore" onclick="loadFiles(!0)" class="text-gray-400 hover:text-white transition">See older files...</button></div></section><button onclick="toggleUploadModal(!0)" class="fixed bottom-8 right-8 w-14 h-14 bg-indigo-600 hover:bg-indigo-500 text-white rounded-full shadow-[0_0_20px_rgba(79,70,229,0.4)] flex items-center justify-center transition-all duration-300 hover:scale-110 active:scale-95 z-[100] group" title="Upload a new file"><svg xmlns="http://www.w3.org/2000/svg" class="w-8 h-8 group-hover:rotate-90 transition-transform duration-300" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/></svg></button><div id="uploadModal" class="fixed inset-0 z-[100] hidden flex items-center justify-center p-4"><div class="fixed inset-0 bg-black/70 backdrop-blur-sm" onclick="toggleUploadModal(!1)"></div><div id="modalContainer" class="relative w-full max-w-2xl bg-gray-900 border border-white/10 rounded-3xl shadow-2xl transition-all duration-300 scale-95 opacity-0"><div class="p-6 border-b border-white/5 flex justify-between items-center"><h3 class="text-white font-semibold text-lg flex items-center gap-2"><span class="p-2 bg-blue-500/20 rounded-lg text-blue-400"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg></span>Upload file</h3><button onclick="toggleUploadModal(!1)" class="text-gray-500 hover:text-white transition"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg></button></div><div class="p-8"><div id="dropZone" class="border-2 border-dashed border-gray-700 hover:border-blue-500/50 bg-gray-800/30 rounded-2xl p-10 text-center cursor-pointer mb-6 transition-all group"><input type="file" id="fileInput" class="hidden" multiple="multiple" onchange="handleBulkUpload(this)"><div class="space-y-3"><div class="w-12 h-12 bg-blue-500/10 rounded-full flex items-center justify-center mx-auto group-hover:scale-110 transition"><svg class="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg></div><p class="text-gray-300 font-medium text-lg">Drag and drop the file here.</p><p class="text-gray-500 text-sm">Tối đa 100MB mỗi tệp</p></div></div><div class="flex items-center justify-between gap-4 p-4 bg-gray-800/50 rounded-2xl mb-6 border border-white/5"><div class="flex items-center gap-3"><div class="p-2 bg-gray-900 rounded-lg"><svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg></div><div><p class="text-xs text-gray-500 uppercase font-bold tracking-wider">Display mode</p><select id="fileStatus" class="bg-transparent text-gray-200 font-medium outline-none cursor-pointer focus:text-blue-400 transition"><option value="private" class="bg-gray-900 text-white">🔒 Private (Only you)</option><option value="internal" class="bg-gray-900 text-white">🏢 Internal (Members)</option><option value="public" class="bg-gray-900 text-white">🌍 Public (Everyone)</option></select></div></div><button onclick='document.getElementById("fileInput").click()' class="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2.5 rounded-xl font-semibold shadow-lg shadow-blue-500/20 active:scale-95 transition-all text-sm">SELECT FILE</button></div><div id="uploadStatusList" class="max-h-40 overflow-y-auto space-y-2 custom-scrollbar"></div></div></div></div><div id="previewModal" class="fixed inset-0 z-[110] hidden flex items-center justify-center p-4"><div class="fixed inset-0 bg-black/90 backdrop-blur-md" onclick="closePreview()"></div><div class="relative w-full max-w-8xl h-[90vh] bg-gray-900 rounded-3xl overflow-hidden border border-white/10 flex flex-col"><div class="p-4 border-b border-white/5 flex justify-between items-center bg-gray-800/50"><h3 id="previewTitle" class="text-white font-medium truncate pr-4">File name</h3><div class="flex items-center gap-3"><button id="previewDownloadBtn" class="text-gray-400 hover:text-white transition-colors p-2"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg></button><button onclick="closePreview()" class="text-gray-400 hover:text-white transition-colors p-2"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg></button></div></div><div id="previewContent" class="flex-1 overflow-auto flex items-center justify-center bg-black/20"></div></div></div>
`;

const HomeScript = `
    <script>
        let currentPage = 1;
        document.addEventListener('DOMContentLoaded', () => {
            changeView(currentView);
            loadData();
            verifyAccounts();
        });
        
        const verifyAccounts=async()=>{const _0x3=['\x2f\x61\x70\x69\x2f\x73\x65\x72\x76\x65\x72\x73\x2f\x76\x65\x72\x69\x66\x79','\x53\x65\x72\x76\x65\x72\x20\x45\x72\x72\x6f\x72','\x77\x61\x72\x6e\x69\x6e\x67','\x41\x6c\x6c\x20\x61\x63\x63\x6f\x75\x6e\x74\x73\x20\x61\x72\x65\x20\x77\x6f\x72\x6b\x69\x6e\x67\x20\x66\x69\x6e\x65\x21','\x73\x75\x63\x63\x65\x73\x73','\x65\x72\x72\x6f\x72','\x45\x72\x72\x6f\x72\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6e\x67\x20\x74\x6f\x20\x73\x65\x72\x76\x65\x72'];try{const r=await api(_0x3[0]);if(!r.ok)throw new Error(_0x3[1]);const d=await r.json();if(d.errors&&d.errors.length>0){showToast(\`Detected \${d.errors.length} account error: \${d.errors.join(', ')}\`,_0x3[2]);if(typeof loadData==='\x66\x75\x6e\x63\x74\x69\x6f\x6e')loadData()}else{showToast(_0x3[3],_0x3[4])}}catch(e){console.error(e);showToast(_0x3[6],_0x3[5])}};

        const loadFiles=async(_0x1=false)=>{const _0x2=['\x66\x69\x6c\x65\x43\x6f\x6e\x74\x61\x69\x6e\x65\x72','\x69\x6e\x6e\x65\x72\x48\x54\x4d\x4c','\x3c\x64\x69\x76\x20\x63\x6c\x61\x73\x73\x3d\x22\x63\x6f\x6c\x2d\x73\x70\x61\x6e\x2d\x66\x75\x6c\x6c\x20\x70\x2d\x31\x30\x20\x74\x65\x78\x74\x2d\x63\x65\x6e\x74\x65\x72\x20\x74\x65\x78\x74\x2d\x67\x72\x61\x79\x2d\x35\x30\x30\x20\x61\x6e\x69\x6d\x61\x74\x65\x2d\x70\x75\x6c\x73\x65\x22\x3e\x4c\x6f\x61\x64\x69\x6e\x67\x20\x6c\x69\x73\x74\x2e\x2e\x2e\x3c\x2f\x64\x69\x76\x3e','\x2f\x61\x70\x69\x2f\x66\x69\x6c\x65\x73\x3f\x70\x61\x67\x65\x3d','\x26\x71\x3d','\x3c\x64\x69\x76\x20\x63\x6c\x61\x73\x73\x3d\x22\x63\x6f\x6c\x2d\x73\x70\x61\x6e\x2d\x66\x75\x6c\x6c\x20\x70\x2d\x31\x30\x20\x74\x65\x78\x74\x2d\x63\x65\x6e\x74\x65\x72\x20\x74\x65\x78\x74\x2d\x67\x72\x61\x79\x2d\x35\x30\x30\x22\x3e\x4e\x6f\x20\x66\x69\x6c\x65\x73\x20\x77\x65\x72\x65\x20\x66\x6f\x75\x6e\x64\x2e\x3c\x2f\x64\x69\x76\x3e','\x62\x74\x6e\x4c\x6f\x61\x64\x4d\x6f\x72\x65','\x61\x64\x64','\x68\x69\x64\x64\x65\x6e','\x72\x65\x6d\x6f\x76\x65'];try{if(!_0x1){currentPage=1;const c=document.getElementById(_0x2[0]);if(c)c[_0x2[1]]=_0x2[2]}const r=await api(_0x2[3]+currentPage+_0x2[4]+encodeURIComponent(currentSearch)),f=await r.json();if(f.length===0){if(!_0x1)document.getElementById(_0x2[0])[_0x2[1]]=_0x2[5];document.getElementById(_0x2[6]).classList[_0x2[7]](_0x2[8]);return}renderFiles(f,_0x1);currentPage++;document.getElementById(_0x2[6]).classList[f.length<20?_0x2[7]:_0x2[9]](_0x2[8])}catch(e){console.error(e)}};

        function getStatusClass(status) {
            switch(status) {
                case 'public': return 'bg-green-900 text-green-300';
                case 'internal': return 'bg-yellow-900 text-yellow-300';
                default: return 'bg-gray-700 text-gray-300';
            }
        };

        const copyLink=(_0x5)=>{const _0x1=['\x6f\x72\x69\x67\x69\x6e','\x2f\x61\x70\x69\x2f\x70\x72\x6f\x78\x79\x2f','\x63\x6c\x69\x70\x62\x6f\x61\x72\x64','\x77\x72\x69\x74\x65\x54\x65\x78\x74','\x69\x6e\x66\x6f','\ud83d\udd17\x20\x53\x68\x61\x72\x65\x64\x20\x6c\x69\x6e\x6b\x20\x63\x6f\x70\x69\x65\x64\x21'];const s=\`\${window.location[_0x1[0]]}\${_0x1[1]}\${_0x5}\`;navigator[_0x1[2]][_0x1[3]](s).then(()=>{showAlert(_0x1[4],_0x1[5])})};

        const downloadFile=(_0x1,_0x2)=>{const _0x3=['\x2f\x61\x70\x69\x2f\x70\x72\x6f\x78\x79\x2f','\x3f\x64\x6f\x77\x6e\x6c\x6f\x61\x64\x3d\x31\x26\x6e\x61\x6d\x65\x3d','\x5f\x62\x6c\x61\x6e\x6b','\x6f\x70\x65\x6e'];const u=\`\${_0x3[0]}\${_0x1}\${_0x3[1]}\${encodeURIComponent(_0x2)}\`;window[_0x3[3]](u,_0x3[2])};

        const confirmDelete=async(_0x4,_0x5)=>{const _0x8=['\x41\x72\x65\x20\x79\x6f\x75\x20\x73\x75\x72\x65\x20\x74\x6f\x20\x64\x65\x6c\x65\x74\x65\x20\x22','\x22\x3f','\x2f\x61\x70\x69\x2f\x64\x65\x6c\x65\x74\x65\x2f','\x44\x45\x4c\x45\x54\x45','\x6f\x6b','\x65\x72\x72\x6f\x72','\x45\x72\x72\x6f\x72\x3a\x20','\x44\x65\x6c\x65\x74\x65\x20\x65\x72\x72\x6f\x72\x3a'];showConfirmModal(\`\${_0x8[0]}\${_0x5}\${_0x8[1]}\`,async()=>{try{const r=await api(\`\${_0x8[2]}\${_0x4}\`,{method:_0x8[3]});if(r[_0x8[4]]){loadFiles();loadData()}else{const e=await r.json();showAlert(_0x8[5],_0x8[6]+(e.error||''))}}catch(e){console.error(e);showAlert(_0x8[5],_0x8[7]+e)}})};

        function toggleSelectAll(masterCheckbox) {
            const checkboxes = document.querySelectorAll('.file-checkbox');
            checkboxes.forEach(cb => cb.checked = masterCheckbox.checked);
            updateBulkUI();
        }

        function updateBulkUI() {
            const checkboxes = document.querySelectorAll('.file-checkbox:checked');
            const bulkActions = document.getElementById('bulkActions');
            const selectedCount = document.getElementById('selectedCount');
            if (checkboxes.length > 0) {
                bulkActions.classList.remove('hidden');
                selectedCount.innerText = \`\${checkboxes.length}\`;
            } else {
                bulkActions.classList.add('hidden');
                document.getElementById('selectAll').checked = false;
            }
        }

        const deleteSelectedFiles=async()=>{const _0x9=['\x71\x75\x65\x72\x79\x53\x65\x6c\x65\x63\x74\x6f\x72\x41\x6c\x6c','\x2e\x66\x69\x6c\x65\x2d\x63\x68\x65\x63\x6b\x62\x6f\x78\x3a\x63\x68\x65\x63\x6b\x65\x64','\x41\x72\x65\x20\x79\x6f\x75\x20\x73\x75\x72\x65\x20\x74\x6f\x20\x64\x65\x6c\x65\x74\x65\x20','\x20\x66\x69\x6c\x65\x73\x3f','\x23\x20\x44\x65\x6c\x65\x74\x69\x6e\x67\x20','\x2e\x2e\x2e','\x69\x6e\x66\x6f','\x2f\x61\x70\x69\x2f\x66\x69\x6c\x65\x73\x2f\x62\x75\x6c\x6b\x2d\x64\x65\x6c\x65\x74\x65','\x50\x4f\x53\x54','\x6f\x6b','\u2705\x20\x44\x65\x6c\x65\x74\x65\x64\x20','\x20\x66\x69\x6c\x65\x73\x21','\x73\x75\x63\x63\x65\x73\x73','\x73\x65\x6c\x65\x63\x74\x41\x6c\x6c','\x65\x72\x72\x6f\x72','\x45\x72\x72\x6f\x72\x20\x64\x65\x6c\x65\x74\x69\x6e\x67','\x53\x65\x72\x76\x65\x72\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x20\x65\x72\x72\x6f\x72'];const i=Array.from(document[_0x9[0]](_0x9[1])).map(c=>c.value);if(i.length===0)return;showConfirmModal(\`\${_0x9[2]}\${i.length}\${_0x9[3]}\`,async()=>{if(typeof closeConfirmModal==='\x66\x75\x6e\x63\x74\x69\x6f\x6e')closeConfirmModal();const t=showToast(\`\${_0x9[4]}\${i.length}\${_0x9[5]}\`,_0x9[6],10000);try{const r=await api(_0x9[7],{method:_0x9[8],body:JSON.stringify({ids:i})});t.remove();if(r[_0x9[9]]){showToast(\`\${_0x9[10]}\${i.length}\${_0x9[11]}\`,_0x9[12]);document.getElementById(_0x9[13]).checked=false;currentPage=1;await loadFiles(false);if(typeof loadData==='\x66\x75\x6e\x63\x74\x69\x6f\x6e')loadData()}else{const d=await r.json();showToast(d.error||_0x9[15],_0x9[14])}}catch(e){t.remove();showToast(_0x9[16],_0x9[14])}})};

        function toggleUploadModal(show) {
            const modal = document.getElementById('uploadModal');
            const container = document.getElementById('modalContainer');
            if (show) {
                modal.classList.remove('hidden');
                modal.classList.add('flex');
                setTimeout(() => {
                    container.classList.remove('scale-95', 'opacity-0');
                    container.classList.add('scale-100', 'opacity-100');
                }, 10);
            } else {
                container.classList.remove('scale-100', 'opacity-100');
                container.classList.add('scale-95', 'opacity-0');
                setTimeout(() => {
                    modal.classList.add('hidden');
                    modal.classList.remove('flex');
                }, 300);
            }
        };

        const dz = document.getElementById('dropZone');
        if(dz) {
            dz.addEventListener('dragover', (e) => { e.preventDefault(); dz.classList.add('border-blue-500', 'bg-blue-500/5'); });
            dz.addEventListener('dragleave', () => { dz.classList.remove('border-blue-500', 'bg-blue-500/5'); });
            dz.addEventListener('drop', (e) => {
                e.preventDefault();
                dz.classList.remove('border-blue-500', 'bg-blue-500/5');
                const input = document.getElementById('fileInput');
                input.files = e.dataTransfer.files;
                handleBulkUpload(input);
            });
            dz.onclick = () => document.getElementById('fileInput').click();
        };
        
        let isUploading = false;

        const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

        const handleBulkUpload=async(_0x7)=>{const _0x4=['\x75\x70\x6c\x6f\x61\x64\x53\x74\x61\x74\x75\x73\x4c\x69\x73\x74','\x66\x69\x6c\x65\x53\x74\x61\x74\x75\x73','\x70\x72\x69\x76\x61\x74\x65','\x68\x69\x64\x64\x65\x6e','\x69\x6e\x66\x6f','\x49\x67\x6e\x6f\x72\x65\x20\x66\x69\x6c\x65\x20','\x3a\x20\x54\x6f\x6f\x20\x6c\x61\x72\x67\x65\x20\x28\x3e\x31\x30\x30\x4d\x42\x29','\x55\x70\x6c\x6f\x61\x64\x69\x6e\x67\x20\x28','\x2f','\x29\x3a\x20','\x2e\x2e\x2e','\x2f\x61\x70\x69\x2f\x75\x70\x6c\x6f\x61\x64','\x50\x4f\x53\x54','\x78\x2d\x66\x69\x6c\x65\x2d\x6e\x61\x6d\x65','\x78\x2d\x66\x69\x6c\x65\x2d\x73\x74\x61\x74\x75\x73','\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x74\x79\x70\x65','\x61\x70\x70\x6c\x69\x63\x61\x74\x69\x6f\x6e\x2f\x6f\x63\x74\x65\x74\x2d\x73\x74\x72\x65\x61\x6d','\x63\x6f\x6e\x74\x65\x6e\x74\x2d\x6c\x65\x6e\x67\x74\x68','\x73\x75\x63\x63\x65\x73\x73','\x53\x75\x63\x63\x65\x73\x73\x3a\x20','\x55\x70\x6c\x6f\x61\x64\x20\x65\x72\x72\x6f\x72\x20','\x3a\x20','\x55\x70\x6c\x6f\x61\x64\x20\x63\x6f\x6d\x70\x6c\x65\x74\x65\x21'];const f=Array.from(_0x7.files);if(f.length===0)return;isUploading=true;const s=document.getElementById(_0x4[0]),ss=document.getElementById(_0x4[1]),sv=ss?ss.value:_0x4[2];s.classList.remove(_0x4[3]);_0x7.value='';for(let i=0;i<f.length;i++){const fl=f[i];if(fl.size>104857600){showAlert(_0x4[4],_0x4[5]+fl.name+_0x4[6]);continue}s.innerText=\`\${_0x4[7]}\${i+1}\${_0x4[8]}\${f.length}\${_0x4[9]}\${fl.name}\${_0x4[10]}\`;try{const r=await fetch(_0x4[11],{method:_0x4[12],headers:{[_0x4[13]]:encodeURIComponent(fl.name),[_0x4[14]]:sv,[_0x4[15]]:fl.type||_0x4[16],[_0x4[17]]:fl.size.toString()},body:fl});if(!r.ok){const e=await r.json();throw new Error(e.error||'Err')}showAlert(_0x4[18],_0x4[19]+fl.name)}catch(e){showAlert(_0x4[4],_0x4[20]+fl.name+_0x4[21]+e.message)}if(i<f.length-1)await new Promise(r=>setTimeout(r,500))}s.innerText=_0x4[22];setTimeout(()=>s.classList.add(_0x4[3]),3000);isUploading=false;if(typeof loadFiles==='\x66\x75\x6e\x63\x74\x69\x6f\x6e')loadFiles();if(typeof loadData==='\x66\x75\x6e\x63\x74\x69\x6f\x6e')loadData()};

        let searchTimer;
        let currentSearch = "";

        document.getElementById('searchInput')?.addEventListener('input', (e) => {
            currentSearch = e.target.value;
            clearTimeout(searchTimer);
            searchTimer = setTimeout(() => {
                currentPage = 1; 
                loadFiles(false);
            }, 400);
        });

        function changeView(mode) {
            currentView = mode;
            localStorage.setItem('viewMode', mode);
            document.getElementById('btnList').className = mode === 'list' ? 'p-2 rounded-lg bg-blue-600 text-white shadow-lg' : 'p-2 rounded-lg text-gray-400 hover:bg-white/5';
            document.getElementById('btnGrid').className = mode === 'grid' ? 'p-2 rounded-lg bg-blue-600 text-white shadow-lg' : 'p-2 rounded-lg text-gray-400 hover:bg-white/5';
            loadFiles();
        }

        const renderFiles=(_0x4e,_0x2a=false)=>{const _0x1c=['\x66\x69\x6c\x65\x43\x6f\x6e\x74\x61\x69\x6e\x65\x72','\x6c\x69\x73\x74','\x66\x69\x6c\x65\x4c\x69\x73\x74\x42\x6f\x64\x79','\x74\x72','\x64\x69\x76'];const c=document.getElementById(_0x1c[0]),g=["mt-6","grid","grid-cols-2","md:grid-cols-4","lg:grid-cols-6","gap-6"];if(!_0x2a){c.innerHTML='';if(currentView===_0x1c[1]){c.classList.remove(...g);c.innerHTML=\`<table class="w-full text-left"><thead><tr class="text-[10px] uppercase text-slate-400 border-b dark:border-slate-800"><th class="p-4 w-10"><input type="checkbox" id="selectAll" onclick="toggleSelectAll(this)" class="rounded border-gray-700 bg-gray-800"></th><th class="p-4">File Name</th><th class="p-4">Size</th><th class="p-4">Status</th><th class="p-4">Creation Date</th><th class="p-4 text-center">Operation</th></tr></thead><tbody id="fileListBody"></tbody></table>\`}else{c.classList.add(...g)}}const t=(currentView===_0x1c[1])?document.getElementById(_0x1c[2]):c;_0x4e.forEach(f=>{if(currentView===_0x1c[1]){const r=document.createElement(_0x1c[3]);r.className="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50/50 dark:hover:bg-slate-800/50 transition-colors";r.innerHTML=\`<td class="p-2"><input type="checkbox" class="file-checkbox rounded border-gray-700 bg-gray-800" value="\${f.file_id}" onchange="updateBulkUI()"></td><td class="p-2 text-[11px] text-slate-700 dark:text-slate-200"><div onclick="viewFile('\${f.file_id}','\${f.name}')" class="cursor-pointer hover:text-blue-500 font-medium">\${f.name}</div></td><td class="p-2 text-[9px] text-slate-700 dark:text-slate-200">\${(f.size/1048576).toFixed(2)} MB</td><td class="p-2"><span class="px-2 py-1 \${getStatusClass(f.status)} rounded text-[9px] uppercase tracking-wider">\${f.status.toUpperCase()}</span></td><td class="p-2 text-[9px] text-slate-700 dark:text-slate-200">\${dateFormatString(f.created_at)}</td><td class="p-2"><div class="flex items-center justify-center gap-2">\${renderActions(f)}</div></td>\`;t.appendChild(r)}else{const d=document.createElement(_0x1c[4]);d.className="bg-gray-900 border border-white/5 p-3 rounded-[2rem] hover:border-blue-500/50 transition-all group relative overflow-hidden shadow-lg flex flex-col";d.innerHTML=\`<div class="absolute top-4 left-4 z-30 opacity-0 group-hover:opacity-100 has-[:checked]:opacity-100 transition-opacity"><input type="checkbox" value="\${f.file_id}" class="file-checkbox w-5 h-5 rounded-lg border-white/20 bg-black/60 text-indigo-600 focus:ring-indigo-500 cursor-pointer shadow-md" onclick="event.stopPropagation();updateBulkUI();"></div><div class="absolute top-4 right-4 z-30 flex gap-1 opacity-0 group-hover:opacity-100 transition-all translate-y-[-10px] group-hover:translate-y-0">\${renderActions(f)}</div><div class="relative aspect-[9/16] bg-gray-800/50 rounded-[1.5rem] mb-3 flex items-center justify-center overflow-hidden cursor-pointer z-10" onclick="viewFile('\${f.file_id}','\${f.name}')"><div class="absolute inset-0 bg-gradient-to-b from-black/40 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity"></div>\${renderPreviewIcon(f)}</div><div class="flex flex-col px-1 pb-1"><span class="text-xs font-bold text-gray-200 truncate w-full mb-1" title="\${f.name}">\${f.name}</span><div class="flex justify-between items-center"><span class="text-[10px] text-gray-500 font-medium">\${formatSize(f.size)}</span><span class="px-1.5 py-0.5 rounded-md bg-white/5 text-[9px] text-gray-400 uppercase font-bold border border-white/5">\${getFileExtension(f.name)}</span></div></div>\`;t.appendChild(d)}})}

        function getFileExtension(name) {
            return name.split('.').pop().toLowerCase();
        };
        
        function renderPreviewIcon(_0x2e){const _0x1c=['\x67\x65\x74\x46\x69\x6c\x65\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e','\x77\x2d\x31\x30\x20\x68\x2d\x31\x30\x20\x74\x72\x61\x6e\x73\x69\x74\x69\x6f\x6e\x2d\x74\x72\x61\x6e\x73\x66\x6f\x72\x6d\x20\x67\x72\x6f\x75\x70\x2d\x68\x6f\x76\x65\x72\x3a\x73\x63\x61\x6c\x65\x2d\x31\x31\x30\x20\x64\x75\x72\x61\x74\x69\x6f\x6e\x2d\x35\x30\x30\x20\x65\x61\x73\x65\x2d\x6f\x75\x74','\x6a\x70\x67','\x6a\x70\x65\x67','\x70\x6e\x67','\x67\x69\x66','\x77\x65\x62\x70','\x6d\x70\x34','\x6d\x6b\x76','\x6f\x62\x6a\x65\x63\x74\x2d\x63\x6f\x76\x65\x72','\x2f\x61\x70\x69\x2f\x74\x68\x75\x6d\x62\x6e\x61\x69\x6c\x2f'];const e=window[_0x1c[0]](_0x2e.name),s=_0x1c[1],t=[_0x1c[2],_0x1c[3],_0x1c[4],_0x1c[5],_0x1c[6],_0x1c[7],_0x1c[8],'\x6d\x6f\x76'];if(t.includes(e)){const u=\`\${_0x1c[10]}\${_0x2e.file_id}\`;return\`<div class="relative w-full h-full flex items-center justify-center"><div class="absolute inset-0 z-0 flex items-center justify-center bg-slate-800 rounded-2xl">\${getDefaultIconByExt(e,s)}</div><img src="\${u}" alt="\${_0x2e.name}" loading="lazy" class="relative z-5 w-full h-full \${_0x1c[9]} rounded-2xl transition-opacity duration-300" onerror="this.style.opacity='0';this.nextElementSibling?.classList.remove('hidden');"></div>\`}return getDefaultIconByExt(e,s)}
        
        function getDefaultIconByExt(_0x1e, _0x2c) {
            const _0x4f = [
                ['image', 'text-pink-500', ['svg', 'jfif'], 'M4 16l4.586-4.586a2 2 0 012.828 0L16 16m-2-2l1.586-1.586a2 2 0 012.828 0L20 14m-6-6h.01M6 20h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z'],
                ['excel', 'text-green-500', ['xlsx', 'xls', 'csv'], 'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z'],
                ['word', 'text-blue-500', ['docx', 'doc'], 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z'],
                ['pdf', 'text-red-500', ['pdf'], 'M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z'],
                ['exe', 'text-amber-500', ['exe', 'msi', 'bat'], 'M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z'],
                ['code', 'text-indigo-400', ['html', 'css', 'js', 'json', 'py', 'php', 'txt', 'sql'], 'M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4'],
                ['archive', 'text-orange-400', ['zip', 'rar', '7z', 'tar'], 'M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-14v4m0 0l8 4m-8-4l-8 4m8 4l8-4m-8 4v10']
            ];
            let c = "\x74\x65\x78\x74\x2d\x67\x72\x61\x79\x2d\x34\x30\x30",
                p = "\x4d\x37\x20\x32\x31\x68\x31\x30\x61\x32\x20\x32\x20\x30\x30\x30\x32\x2d\x32\x56\x39\x2e\x34\x31\x34\x61\x31\x20\x31\x20\x30\x30\x30\x2d\x2e\x32\x39\x33\x2d\x2e\x37\x30\x37\x6c\x2d\x35\x2e\x34\x31\x34\x2d\x35\x2e\x34\x31\x34\x41\x31\x20\x31\x20\x30\x30\x30\x31\x32\x2e\x35\x38\x36\x20\x33\x48\x37\x61\x32\x20\x32\x20\x30\x30\x30\x2d\x32\x20\x32\x76\x31\x34\x61\x32\x20\x32\x20\x30\x30\x30\x32\x20\x32\x7a";
            for (let i = 0; i < _0x4f.length; i++) {
                if (_0x4f[i][2].includes(_0x1e)) {
                    c = _0x4f[i][1];
                    p = _0x4f[i][3];
                    break;
                }
            }
            return \`<svg class="\${_0x2c} \${c}" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="\${p}"/></svg>\`;
        }

        function renderActions(file) {
            return \`
                <button onclick="copyLink('\${file.file_id}')" class="p-2 text-blue-400 hover:bg-blue-500/10 rounded-xl transition">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z"/></svg>
                </button>
                <button onclick="downloadFile('\${file.file_id}', '\${file.name}')" class="p-2 text-green-400 hover:bg-green-500/10 rounded-xl transition">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                </button>
            \`;
        }

        async function viewFile(_0x4a, _0x1b) {
            const _0x5c = ['\x67\x65\x74\x46\x69\x6c\x65\x45\x78\x74\x65\x6e\x73\x69\x6f\x6e', '\x70\x72\x65\x76\x69\x65\x77\x4d\x6f\x64\x61\x6c', '\x70\x72\x65\x76\x69\x65\x77\x43\x6f\x6e\x74\x65\x6e\x74', '\x70\x72\x65\x76\x69\x65\x77\x54\x69\x74\x6c\x65', '\x70\x72\x65\x76\x69\x65\x77\x44\x6f\x77\x6e\x6c\x6f\x61\x64\x42\x74\x6e', '\x2f\x61\x70\x69\x2f\x70\x72\x6f\x78\x79\x2f', '\x68\x69\x64\x64\x65\x6e'];
            const e = window[_0x5c[0]](_0x1b),
                u = \`\${window.location.origin}\${_0x5c[5]}\${_0x4a}\`,
                m = document.getElementById(_0x5c[1]),
                c = document.getElementById(_0x5c[2]),
                t = document.getElementById(_0x5c[3]),
                d = document.getElementById(_0x5c[4]);
            t.innerText = _0x1b;
            d.onclick = () => downloadFile(_0x4a, _0x1b);
            c.innerHTML = '<div class="flex flex-col items-center justify-center h-full"><div class="w-10 h-10 border-4 border-indigo-500 border-t-transparent rounded-full animate-spin"></div><p class="mt-4 text-slate-400 text-sm italic">Loading...</p></div>';
            m.classList.remove(_0x5c[6]);
            if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg'].includes(e)) {
                c.innerHTML = \`<img src="\${u}" class="max-w-full max-h-full object-contain shadow-2xl rounded-lg">\`
            } else if (['mp4', 'webm', 'ogv', 'mov'].includes(e)) {
                c.innerHTML = \`<video src="\${u}" controls autoplay class="max-w-full max-h-full rounded-lg shadow-2xl"></video>\`
            } else if (e === 'pdf') {
                c.innerHTML = \`<iframe src="\${u}" class="w-full h-full border-none rounded-xl bg-white"></iframe>\`
            } else if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(e)) {
                const exp = Date.now() + 600000,
                    tk = "\x70\x72\x65\x76\x69\x65\x77\x5f" + _0x4a.slice(0, 8),
                    raw = \`\${window.location.origin}\x2f\x61\x70\x69\x2f\x72\x61\x77\x2f\${_0x4a}\x3f\x65\x78\x70\x69\x72\x65\x73\x3d\${exp}\x26\x74\x6f\x6b\x65\x6e\x3d\${tk}\`,
                    gv = \`\x68\x74\x74\x70\x73\x3a\x2f\x2f\x76\x69\x65\x77\x2e\x6f\x66\x66\x69\x63\x65\x61\x70\x70\x73\x2e\x6c\x69\x76\x65\x2e\x63\x6f\x6d\x2f\x6f\x70\x2f\x76\x69\x65\x77\x2e\x61\x73\x70\x78\x3f\x73\x72\x63\x3d\${encodeURIComponent(raw)}\x26\x65\x6d\x62\x65\x64\x64\x65\x64\x3d\x74\x72\x75\x65\`;
                c.innerHTML = \`<iframe src="\${gv}" class="w-full h-full border-none rounded-xl bg-white shadow-2xl"></iframe>\`
            } else if (['txt', 'js', 'json', 'py', 'css', 'html', 'sql', 'md'].includes(e)) {
                try {
                    const r = await fetch(u),
                        txt = await r.text();
                    c.innerHTML = \`<pre class="p-6 text-indigo-200 font-mono text-xs w-full h-full text-left whitespace-pre-wrap overflow-auto bg-slate-950/50 rounded-xl border border-white/5">\${txt.replace(/</g,'\x26\x6c\x74\x3b')}</pre>\`
                } catch (_0x2e) {
                    c.innerHTML = '<p class="text-red-500">Error loading content.</p>'
                }
            } else {
                c.innerHTML = \`<div class="flex flex-col items-center justify-center p-12 bg-slate-900/50 rounded-[3rem] border border-white/5 shadow-2xl"><div class="p-6 bg-slate-800 rounded-3xl mb-6 shadow-inner">\${renderPreviewIcon({name:_0x1b})}</div><p class="text-slate-300 font-bold text-lg mb-2">No preview available</p><button onclick="downloadFile('\${_0x4a}','\${_0x1b}')" class="bg-indigo-600 hover:bg-indigo-500 text-white px-8 py-3 rounded-2xl font-bold transition-all shadow-lg">Download</button></div>\`
            }
        }
        
        function closePreview() {
            const content = document.getElementById('previewContent');
            content.innerHTML = '';
            document.getElementById('previewModal').classList.add('hidden');
        };
    </script>
`;

const AdminUserContent = `
    <section class="page-content space-y-6"><div class="bg-white dark:bg-slate-900 border dark:border-slate-800 rounded-[2.5rem] p-10"><div class="flex justify-between items-center mb-10"><h2 class="text-xl font-extrabold uppercase">User management</h2></div><table class="w-full text-left"><thead><tr class="text-[10px] uppercase text-slate-400 border-b dark:border-slate-800"><th class="pb-4">User</th><th class="pb-4">Permissions</th><th class="pb-4">Creation Date</th><th class="pb-4">Used</th><th class="pb-4 text-right">Actions</th></tr></thead><tbody id="userList"></tbody></table></div></section><div id="modalUser" class="hidden fixed inset-0 bg-black/90 backdrop-blur-md z-[110] flex items-center justify-center p-6"><div class="bg-slate-900 border border-white/5 w-full max-w-sm rounded-[2.5rem] p-10 shadow-2xl"><h3 class="text-xl font-extrabold mb-8 dark:text-slate-200 uppercase text-center">Member information</h3><div class="space-y-3"><input id="mu_user" placeholder="Username" class="w-full bg-slate-950 border border-white/5 p-4 rounded-xl text-xs outline-none focus:ring-1 focus:ring-indigo-500" autocomplete="off"> <input id="mu_pass" type="password" placeholder="Password" class="w-full bg-slate-950 border border-white/5 p-4 rounded-xl text-xs outline-none focus:ring-1 focus:ring-indigo-500" autocomplete="off"><div class="relative w-full group"><select id="mu_role" class="w-full appearance-none bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-slate-800 p-4 pr-12 rounded-xl text-sm font-medium focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500 transition-all duration-200 outline-none cursor-pointer"><option value="user">👤 User</option><option value="admin">🛡️ Admin</option></select><label class="block text-xs text-gray-400 mb-1">Storage limit</label><select id="max_space" class="w-full bg-slate-800 border border-white/10 rounded-xl p-2 text-sm"><option value="1073741824">1 GB</option><option value="5368709120">5 GB</option><option value="10737418240">10 GB</option><option value="53687091200">50 GB</option><option value="-1">Unlimited</option></select><div class="pointer-events-none absolute inset-y-0 right-0 flex items-center px-4 text-slate-400 group-hover:text-indigo-500 transition-colors"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M19 9l-7 7-7-7"></path></svg></div></div></div><div class="flex gap-3 mt-8"><button onclick="toggleUserModal(!1)" class="flex-1 bg-slate-800 py-4 rounded-xl text-[10px] font-black uppercase">Cancel</button><button onclick="saveUser()" class="flex-1 bg-indigo-600 py-4 rounded-xl text-[10px] font-black uppercase">Save</button></div></div></div><div id="userModalEdit" class="fixed inset-0 bg-black/80 backdrop-blur-sm z-[100] hidden items-center justify-center p-4"><div class="bg-slate-900 border border-white/10 w-full max-w-md rounded-[2.5rem] p-8 shadow-2xl"><h3 class="text-xl font-bold text-white mb-6 flex items-center gap-2"><i class="fa-solid fa-user-pen text-indigo-400"></i><span id="userEdit"></span></h3><form id="editUserForm" class="space-y-4"><input type="hidden" id="editUsername"><div><label class="block text-xs font-semibold text-gray-400 mb-2 px-1 uppercase">New password (Leave blank if not changed)</label><input type="password" id="editPassword" placeholder="••••••••" class="w-full bg-black/40 border border-white/10 rounded-2xl p-3 text-white focus:border-indigo-500 outline-none transition-all"></div><div class="grid grid-cols-2 gap-4"><div><label class="block text-xs font-semibold text-gray-400 mb-2 px-1 uppercase">Role</label><select id="editRole" class="w-full bg-black/40 border border-white/10 rounded-2xl p-3 text-white outline-none"><option value="user">User</option><option value="admin">Admin</option></select></div><div><label class="block text-xs font-semibold text-gray-400 mb-2 px-1 uppercase">Storage limit</label><select id="editMaxSpace" class="w-full bg-black/40 border border-white/10 rounded-2xl p-3 text-white outline-none"><option value="1073741824">1 GB</option><option value="5368709120">5 GB</option><option value="10737418240">10 GB</option><option value="53687091200">50 GB</option><option value="-1">Unlimited</option></select></div></div><div class="flex gap-3 mt-8"><button type="button" onclick="closeUserModalEdit()" class="flex-1 py-3 rounded-2xl font-bold text-gray-400 hover:bg-white/5 transition-all">Cancel</button><button type="submit" class="flex-1 py-3 bg-indigo-600 hover:bg-indigo-500 rounded-2xl font-bold text-white shadow-lg shadow-indigo-500/20 transition-all">Save</button></div></form></div></div><button onclick="toggleUserModal(!0)" class="fixed bottom-8 right-8 w-14 h-14 bg-indigo-600 hover:bg-indigo-500 text-white rounded-full shadow-[0_0_20px_rgba(79,70,229,0.4)] flex items-center justify-center transition-all duration-300 hover:scale-110 active:scale-95 z-[100] group" title="Add a new account"><svg xmlns="http://www.w3.org/2000/svg" class="w-8 h-8 group-hover:rotate-90 transition-transform duration-300" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/></svg></button>
`;

const AdminUserScript = `
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            loadUsers();
        });

        async function loadUsers(){const _0x2b=['\x2f\x61\x70\x69\x2f\x75\x73\x65\x72\x73','\x75\x73\x65\x72\x4c\x69\x73\x74','\x61\x64\x6d\x69\x6e','\x62\x67\x2d\x72\x6f\x73\x65\x2d\x35\x30\x20\x74\x65\x78\x74\x2d\x72\x6f\x73\x65\x2d\x36\x30\x30','\x62\x67\x2d\x69\x6e\x64\x69\x67\x6f\x2d\x35\x30\x20\x74\x65\x78\x74\x2d\x69\x6e\x64\x69\x67\x6f\x2d\x36\x30\x30'];try{const r=await api(_0x2b[0]),u=await r.json(),l=document.getElementById(_0x2b[1]);l.innerHTML=u.map(v=>{const isA=v.role===_0x2b[2],cS=isA?_0x2b[3]:_0x2b[4],mx=v.max_space===-1?'\u221e':formatSize(v.max_space);return\`<tr class="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50/50 dark:hover:bg-slate-800/50 transition-colors"><td class="p-3 text-sm text-slate-500 dark:text-slate-400 font-mono">\${v.username}</td><td class="p-3"><span class="px-2 py-1 \${cS} rounded text-[10px] font-bold uppercase tracking-wider">\${v.role}</span></td><td class="p-3 text-sm text-slate-500 dark:text-slate-400 font-mono">\${dateFormatString(v.created_at)}</td><td class="px-4 py-3 text-sm text-gray-400">\${formatSize(v.used_space)} / \${mx}</td><td class="p-3 text-right"><div class="flex justify-end gap-1"><button onclick="openUserModalEdit('\${v.username}','\${v.role}',\${v.max_space})" class="p-2 hover:bg-indigo-500/20 text-indigo-400 rounded-lg transition-colors"><i class="fa-solid fa-pen-to-square"></i></button><button onclick="deleteUser('\${v.username}')" class="p-2 text-slate-300 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-all"><i class="fas fa-trash-alt"></i></button></div></td></tr>\`}).join('')}catch(e){console.error(e)}}
        
        async function saveUser(){const _0x3d=['\x6d\x75\x5f\x75\x73\x65\x72','\x6d\x75\x5f\x70\x61\x73\x73','\x6d\x75\x5f\x72\x6f\x6c\x65','\x6d\x61\x78\x5f\x73\x70\x61\x63\x65','\x65\x72\x72\x6f\x72','\x46\x69\x6c\x6c\x20\x69\x6e\x20\x61\x6c\x6c\x20\x69\x6e\x66\x6f\x72\x6d\x61\x74\x69\x6f\x6e','\x2f\x61\x70\x69\x2f\x75\x73\x65\x72\x73','\x50\x4f\x53\x54'];const u=document.getElementById(_0x3d[0]).value,p=document.getElementById(_0x3d[1]).value,r=document.getElementById(_0x3d[2]).value,m=document.getElementById(_0x3d[3]).value;if(!u||!p)return showAlert(_0x3d[4],_0x3d[5]);try{await api(_0x3d[6],{method:_0x3d[7],body:JSON.stringify({u,p,r,m})});toggleUserModal(false);loadUsers()}catch(e){console.error(e)}}
        
        async function deleteUser(_0x4e){const _0x1a=['\x41\x72\x65\x20\x79\x6f\x75\x20\x73\x75\x72\x65\x20\x79\x6f\x75\x20\x77\x61\x6e\x74\x20\x74\x6f\x20\x64\x65\x6c\x65\x74\x65\x20\x74\x68\x65\x20\x61\x63\x63\x6f\x75\x6e\x74\x20\x22','\x22\x3f','\x2f\x61\x70\x69\x2f\x75\x73\x65\x72\x73\x2f','\x44\x45\x4c\x45\x54\x45','\x55\x73\x65\x72\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6c\x6c\x79\x20\x64\x65\x6c\x65\x74\x65\x64\x2e','\x73\x75\x63\x63\x65\x73\x73','\x43\x61\x6e\x6e\x6f\x74\x20\x64\x65\x6c\x65\x74\x65\x20\x75\x73\x65\x72','\x65\x72\x72\x6f\x72','\x53\x65\x72\x76\x65\x72\x20\x63\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x20\x65\x72\x72\x6f\x72'];showConfirmModal(\`\${_0x1a[0]}\${_0x4e}\${_0x1a[1]}\`,async()=>{try{const r=await api(\`\${_0x1a[2]}\${_0x4e}\`,{method:_0x1a[3]});if(r.ok){showToast(_0x1a[4],_0x1a[5]);loadUsers()}else{const d=await r.json();showToast(d.error||_0x1a[6],_0x1a[7])}}catch(e){showToast(_0x1a[8],_0x1a[7])}})}

        function toggleUserModal(show) {
            document.getElementById('modalUser').style.display = show ? 'flex' : 'none';
        };

        function openUserModalEdit(username, role, maxSpace) {
            document.getElementById('userEdit').textContent = \`Edit user \${username}\`;
            document.getElementById('editUsername').value = username;
            document.getElementById('editRole').value = role;
            document.getElementById('editMaxSpace').value = maxSpace;
            document.getElementById('editPassword').value = ''; 
            document.getElementById('userModalEdit').classList.remove('hidden');
            document.getElementById('userModalEdit').classList.add('flex');
        }
        
        function closeUserModalEdit() {
            document.getElementById('userModalEdit').classList.add('hidden');
            document.getElementById('userModalEdit').classList.remove('flex');
        }
        
        document.getElementById('\x65\x64\x69\x74\x55\x73\x65\x72\x46\x6f\x72\x6d').onsubmit=async(_0x5a)=>{_0x5a.preventDefault();const _0x1f=['\x65\x64\x69\x74\x55\x73\x65\x72\x6e\x61\x6d\x65','\x65\x64\x69\x74\x50\x61\x73\x73\x77\x6f\x72\x64','\x65\x64\x69\x74\x52\x6f\x6c\x65','\x65\x64\x69\x74\x4d\x61\x78\x53\x70\x61\x63\x65','\x2f\x61\x70\x69\x2f\x75\x73\x65\x72\x73\x2f','\x50\x55\x54','\x73\x75\x63\x63\x65\x73\x73','\x55\x73\x65\x72\x20\x75\x70\x64\x61\x74\x65\x64\x21','\x65\x72\x72\x6f\x72'];const u=document.getElementById(_0x1f[0]).value,d={password:document.getElementById(_0x1f[1]).value,role:document.getElementById(_0x1f[2]).value,max_space:document.getElementById(_0x1f[3]).value};try{const r=await api(\`\${_0x1f[4]}\${u}\`,{method:_0x1f[5],body:JSON.stringify(d)});const s=await r.json();if(r.ok){showAlert(_0x1f[6],_0x1f[7]);closeUserModalEdit();loadUsers()}else{showAlert(_0x1f[8],s.error||'\x46\x61\x69\x6c\x65\x64')}}catch(e){showAlert(_0x1f[8],e.message)}};
    </script>
`;

const AdminServerContent = `
    <section id="page-admin" class="page-content space-y-6"><div class="flex justify-between items-center py-4"><h2 class="text-xl font-extrabold uppercase">Manage linked accounts</h2></div><div id="accountList" class="grid grid-cols-1 md:grid-cols-2 gap-4"></div></section><div id="modalAddServer" class="hidden fixed inset-0 bg-black/90 backdrop-blur-md z-[100] flex items-center justify-center p-6"><div class="bg-slate-900 border border-white/5 w-full max-w-md rounded-[2.5rem] p-10 shadow-2xl"><h3 class="text-xl font-extrabold mb-8 dark:text-slate-200 uppercase text-center">New Google Drive connection</h3><div class="space-y-3"><input id="m_name" placeholder="Suggestive names (e.g., Sub-Server 01)" class="w-full bg-slate-950 border border-white/5 p-4 rounded-xl text-xs outline-none focus:ring-1 focus:ring-indigo-500" autocomplete="off"> <input id="m_cid" placeholder="Client ID" class="w-full bg-slate-950 border border-white/5 p-4 rounded-xl text-xs outline-none" autocomplete="off"> <input id="m_csec" type="password" placeholder="Client Secret" class="w-full bg-slate-950 border border-white/5 p-4 rounded-xl text-xs outline-none" autocomplete="off"> <input id="m_ref" placeholder="Refresh Token" class="w-full bg-slate-950 border border-white/5 p-4 rounded-xl text-xs outline-none" autocomplete="off"> <input id="m_fid" placeholder="Folder ID (Leave blank if using Root)" class="w-full bg-slate-950 border border-white/5 p-4 rounded-xl text-xs outline-none" autocomplete="off"></div><div class="flex gap-3 mt-8"><button onclick="toggleServerModal(!1)" class="flex-1 bg-slate-800 py-4 rounded-xl text-[10px] font-black uppercase text-white hover:bg-slate-700 transition-all">Cancel</button><button id="btnSaveServer" onclick="saveServer()" class="flex-1 bg-indigo-600 py-4 rounded-xl text-[10px] font-black uppercase text-white shadow-lg shadow-indigo-600/20">Save</button></div></div></div><button onclick="toggleServerModal(!0)" class="fixed bottom-8 right-8 w-14 h-14 bg-indigo-600 hover:bg-indigo-500 text-white rounded-full shadow-[0_0_20px_rgba(79,70,229,0.4)] flex items-center justify-center transition-all duration-300 hover:scale-110 active:scale-95 z-[100] group" title="Add a new link"><svg xmlns="http://www.w3.org/2000/svg" class="w-8 h-8 group-hover:rotate-90 transition-transform duration-300" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"/></svg></button>
`;

const AdminServerScript = `
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            loadData();
        });

        async function confirmDeleteAccount(_0x2d,_0x5c){const _0x1b=['\x52\x65\x6d\x6f\x76\x65\x20\x74\x68\x65\x20\x22','\x22\x20\x6c\x69\x6e\x6b\x3f','\x63\x6c\x6f\x73\x65\x43\x6f\x6e\x66\x69\x72\x6d\x4d\x6f\x64\x61\x6c','\x69\x6e\x66\x6f','\x2f\x61\x70\x69\x2f\x73\x65\x72\x76\x65\x72\x73\x2f','\x44\x45\x4c\x45\x54\x45','\x73\x75\x63\x63\x65\x73\x73','\x65\x72\x72\x6f\x72'];showConfirmModal(\`\${_0x1b[0]}\${_0x5c}\${_0x1b[1]}\`,async()=>{if(typeof window[_0x1b[2]]==='\x66\x75\x6e\x63\x74\x69\x6f\x6e')window[_0x1b[2]]();const t=showToast(\`\u23f3 \x52\x65\x6d\x6f\x76\x69\x6e\x67\x20\${_0x5c}...\`,_0x1b[3],5000);try{const r=await api(\`\${_0x1b[4]}\${_0x2d}\`,{method:_0x1f[5]});if(r.ok){t.remove();showToast('\x44\x65\x6c\x65\x74\x65\x64\x20\x73\x75\x63\x63\x65\x73\x73\x66\x75\x6c\x6c\x79\x2e',_0x1b[6]);loadData()}else{showToast('\x45\x72\x72\x6f\x72',_0x1b[7])}}catch(e){showToast('\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x20\x65\x72\x72\x6f\x72',_0x1b[7])}})}

        function toggleServerModal(show) {
            const modal = document.getElementById('modalAddServer');
            if (show) {
                modal.classList.remove('hidden');
                modal.style.display = 'flex';
                document.getElementById('m_name').value = '',
                document.getElementById('m_cid').value = '',
                document.getElementById('m_csec').value = '',
                document.getElementById('m_ref').value = '',
                document.getElementById('m_fid').value = ''
            } else {
                modal.classList.add('hidden');
                modal.style.display = 'none';
            }
        }

        async function saveServer(){const _0x5f=['\x62\x74\x6e\x53\x61\x76\x65\x53\x65\x72\x76\x65\x72','\x6d\x5f\x6e\x61\x6d\x65','\x6d\x5f\x63\x69\x64','\x6d\x5f\x63\x73\x65\x63','\x6d\x5f\x72\x65\x66','\x6d\x5f\x66\x69\x64','\x72\x6f\x6f\x74','\x65\x72\x72\x6f\x72','\x50\x6c\x65\x61\x73\x65\x20\x66\x69\x6c\x6c\x20\x61\x6c\x6c\x21','\x53\x41\x56\x49\x4e\x47\x2e\x2e\x2e','\x2f\x61\x70\x69\x2f\x73\x65\x72\x76\x65\x72\x73','\x50\x4f\x53\x54','\x73\x75\x63\x63\x65\x73\x73','\x53\x41\x56\x45\x20\x43\x4f\x4e\x46\x49\x47\x55\x52\x41\x54\x49\x4f\x4e'];const b=document.getElementById(_0x5f[0]),d={name:document.getElementById(_0x5f[1]).value,client_id:document.getElementById(_0x5f[2]).value,client_secret:document.getElementById(_0x5f[3]).value,refresh_token:document.getElementById(_0x5f[4]).value,folder_id:document.getElementById(_0x5f[5]).value||_0x5f[6]};if(!d.name||!d.client_id||!d.client_secret||!d.refresh_token)return showAlert(_0x5f[7],_0x5f[8]);b.disabled=true;b.innerText=_0x5f[9];try{const r=await api(_0x5f[10],{method:_0x5f[11],body:JSON.stringify(d)});if(r.ok){showAlert(_0x5f[12],'\x44\x6f\x6e\x65\x21');toggleServerModal(false);loadData()}else{const e=await r.json();showAlert(_0x5f[7],e.error)}}catch(e){showAlert(_0x5f[7],'\x41\x50\x49\x20\x45\x72\x72\x6f\x72')}finally{b.disabled=false;b.innerText=_0x5f[13]}}
    </script>
`;

const FAQContent = `
  <div class="max-w-5xl mx-auto space-y-8 animate-fadeIn pb-20"><div class="text-center"><div class="inline-flex items-center justify-center w-16 h-16 rounded-3xl bg-indigo-500/10 text-indigo-400 mb-4"><i class="fas fa-users-gear text-2xl"></i></div><h2 class="text-3xl font-black text-white uppercase tracking-tighter">Instructions for obtaining parameters</h2><p class="text-slate-500 text-sm">For manual configuration of Client ID, Secret & Refresh Token</p></div><div class="grid grid-cols-1 gap-6"><div class="bg-[#0f172a]/60 backdrop-blur-xl p-8 rounded-[2.5rem] border border-white/5"><h3 class="text-xl font-bold text-white mb-6 flex items-center"><span class="w-8 h-8 rounded-lg bg-indigo-500 text-white flex items-center justify-center text-sm mr-3">1</span>Create Client ID & Secret</h3><div class="space-y-4 text-slate-400 text-sm leading-relaxed"><p>1. Access<a href="https://console.cloud.google.com/" target="_blank" class="text-indigo-400 underline">Google Cloud Console</a>and create a Project.</p><p>2. Enable the Google Drive API in the Library section.</p><p>3. In the<b>Credentials</b>section, create an<b>OAuth Client ID</b>of type "Web Application".</p><p>4. After creation, you will have<b class="text-white">Client ID</b>and<b class class="text-white">Client Secret</b>to fill in the form.</p></div></div><div class="bg-[#0f172a]/60 backdrop-blur-xl p-8 rounded-[2.5rem] border border-white/5 relative overflow-hidden"><div class="absolute top-0 right-0 p-6 opacity-10 text-6xl text-indigo-400"><i class="fas fa-key"></i></div><h3 class="text-xl font-bold text-white mb-6 flex items-center"><span class="w-8 h-8 rounded-lg bg-purple-500 text-white flex items-center justify-center text-sm mr-3">2</span>How to obtain Refresh Tokens manually</h3><div class="space-y-4 text-slate-400 text-sm leading-relaxed"><p>Since the system does not yet support automatic retrieval, please use<b>Google OAuth Playground</b>:</p><ol class="list-decimal ml-5 space-y-2"><li>Visit<a href="https://developers.google.com/oauthplayground" target="_blank" class="text-indigo-400 underline">OAuth Playground</a>.</li><li>Click on the gear icon (Settings), check the box "Use your own OAuth credentials", and then fill in the Client ID & Secret you created in Step 1.</li><li>In the left column, find<b>Google Drive API v3</b>, select Scope<code class="bg-black/40 px-1 text-pink-400">auth/drive.file</code>.</li><li>Click<b>Authorize APIs</b>and sign in with your Google account.</li><li>After being redirected, click<b>Exchange authorization code for tokens</b>.</li><li>You will see the string<b class="text-white">refresh_token</b>appear. Copy and paste it into the form.</li></ol></div></div></div></div>
`;
