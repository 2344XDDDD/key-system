const ADMIN_PASSWORD = "XXX285JBHW"; 
export default {
  async fetch(request, env) {
    if (!env.KEYS_DB) {
      return new Response("Error: KV Namespace 'KEYS_DB' not bound.", { status: 500 });
    }
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+/g, '/'); 
    const hwid = url.searchParams.get("hwid");
    const token = url.searchParams.get("token");
    const stage = url.searchParams.get("stage");
    const redirect = url.searchParams.get("redirect");
    const rootUrl = env.ROOT_URL || `${url.protocol}//${url.host}`;
    const htmlResponse = (html) => new Response(html, { headers: { "Content-Type": "text/html; charset=UTF-8" } });
    const jsonResponse = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
    try {
      if (path === "/admin") {
        const config = {
          secret_key: await env.KEYS_DB.get("SECRET_KEY") || "",
          key_mode: await env.KEYS_DB.get("KEY_MODE") || "static",
          provider_type: await env.KEYS_DB.get("PROVIDER_TYPE") || "work",
          work_url: await env.KEYS_DB.get("WORK_URL") || "",
          lv_id: await env.KEYS_DB.get("LV_ID") || "",
          lv_secret: await env.KEYS_DB.get("LV_SECRET") || "",
          ll_link: await env.KEYS_DB.get("LL_LINK") || "",
          ll_secret: await env.KEYS_DB.get("LL_SECRET") || ""
        };
        return htmlResponse(generateAdminHTML(rootUrl, config));
      }

      if (path === "/save-config" && request.method === "POST") {
        const data = await request.json();
        if (String(data.password).trim() !== ADMIN_PASSWORD) return jsonResponse({ success: false, msg: "管理员密码错误" }, 401);
        await env.KEYS_DB.put("SECRET_KEY", data.secret_key || "");
        await env.KEYS_DB.put("KEY_MODE", data.key_mode || "static");
        await env.KEYS_DB.put("PROVIDER_TYPE", data.provider_type || "work");
        await env.KEYS_DB.put("WORK_URL", data.work_url || "");
        await env.KEYS_DB.put("LV_ID", data.lv_id || "");
        await env.KEYS_DB.put("LV_SECRET", data.lv_secret || "");
        await env.KEYS_DB.put("LL_LINK", data.ll_link || "");
        await env.KEYS_DB.put("LL_SECRET", data.ll_secret || "");
        return jsonResponse({ success: true });
      }

      if (path === "/callback") {
        const referer = request.headers.get("Referer") || "";
        let tokenFromReferer = null;
        if (referer.includes("token=")) {
          const match = referer.match(/token=([^&]+)/);
          if (match) tokenFromReferer = match[1];
        }
        const cookie = request.headers.get("Cookie") || "";
        let tokenFromCookie = null;
        if (cookie.includes("ll_token=")) {
          const match = cookie.match(/ll_token=([^;]+)/);
          if (match) tokenFromCookie = match[1];
        }
        const finalToken = token || tokenFromCookie || tokenFromReferer;
        if (!finalToken) {
          return htmlResponse(generateStatusHTML("Error", "无法验证广告完成状态。请重新开始验证流程。", true));
        }
        return Response.redirect(`${rootUrl}/verify-finish?token=${finalToken}`, 302);
      }
      if (path === "/getlink") {
        if (!hwid) return jsonResponse({ status: "error", msg: "Missing HWID" }, 400);
        let activeKey = await env.KEYS_DB.get(`active_key_${hwid}`);
        const userAgent = request.headers.get("User-Agent") || "";
        const isBrowser = userAgent.includes("Mozilla") || userAgent.includes("Chrome");

        if (activeKey) {
          return isBrowser ? htmlResponse(generateStatusHTML("Verified", `Your Key: <b style='color:#fff'>${activeKey}</b>`, false)) : jsonResponse({ status: "completed", key: activeKey });
        }
        const currentStage = parseInt(await env.KEYS_DB.get(`stage_${hwid}`) || "0");
        if (currentStage >= 3) {
          const finalKey = "KEY-" + Math.random().toString(36).substring(2, 10).toUpperCase();
          await env.KEYS_DB.put(`active_key_${hwid}`, finalKey, { expirationTtl: 86400 });
          return isBrowser ? htmlResponse(generateStatusHTML("Success", `第3阶段完成！卡密 24h 有效：<br><br><b style="color:#fff; font-size:24px;">${finalKey}</b>`, false)) : jsonResponse({ status: "completed", key: finalKey });
        }

        const randomToken = Math.random().toString(36).substring(2, 15);
        await env.KEYS_DB.put(`pending_${randomToken}`, JSON.stringify({ 
          hwid, 
          currentStage: currentStage,
          nextStage: currentStage + 1
        }), { expirationTtl: 3600 });

        const verifyPageUrl = `${rootUrl}/start?token=${randomToken}`;
        return isBrowser ? Response.redirect(verifyPageUrl, 302) : jsonResponse({ 
          status: "todo", 
          link: verifyPageUrl, 
          stage: currentStage,
          nextStage: currentStage + 1 
        });
      }

      if (path === "/start") {
        if (!token) return htmlResponse(generateStatusHTML("Error", "无效 Token", true));
        const pendingData = await env.KEYS_DB.get(`pending_${token}`);
        if (!pendingData) return htmlResponse(generateStatusHTML("Security", "验证已失效，请重新从脚本复制链接。", true));
        const { hwid, currentStage, nextStage } = JSON.parse(pendingData);
        const type = await env.KEYS_DB.get("PROVIDER_TYPE") || "work";
        let finalAdLink = "";
        if (type === "work") {
          const workUrl = await env.KEYS_DB.get("WORK_URL") || "";
          const callbackUrl = `${rootUrl}/verify-finish?token=${token}`;
          const b64Callback = btoa(callbackUrl);
          finalAdLink = workUrl.includes("?") ? `${workUrl}&r=${b64Callback}` : `${workUrl}?r=${b64Callback}`;
        } else if (type === "linkvertise") {
          const lvId = await env.KEYS_DB.get("LV_ID") || "";
          const callbackUrl = `${rootUrl}/verify-finish?token=${token}`;
          const b64Callback = btoa(callbackUrl);
          finalAdLink = `https://link-to.net/${lvId}/dynamic?r=${b64Callback}`;
        } else if (type === "lootlabs") {
          let llBase = await env.KEYS_DB.get("LL_LINK") || "";
          finalAdLink = llBase;
          const html = generateStartVerifyHTML(finalAdLink, currentStage, nextStage, rootUrl, hwid, token);
          return new Response(html, {
            headers: {
              "Content-Type": "text/html; charset=UTF-8",
              "Set-Cookie": `ll_token=${token}; Path=/; HttpOnly; Max-Age=3600`
            }
          });
        }

        return htmlResponse(generateStartVerifyHTML(finalAdLink, currentStage, nextStage, rootUrl, hwid, token));
      }

      if (path === "/verify-finish") {
        if (!token) {
          const cookie = request.headers.get("Cookie") || "";
          if (cookie.includes("ll_token=")) {
            const match = cookie.match(/ll_token=([^;]+)/);
            if (match) {
              const cookieToken = match[1];
              const pendingData = await env.KEYS_DB.get(`pending_${cookieToken}`);
              if (pendingData) {
                return Response.redirect(`${rootUrl}/verify-finish?token=${cookieToken}`, 302);
              }
            }
          }
          return htmlResponse(generateStatusHTML("Error", "Token缺失", true));
        }
        const pendingData = await env.KEYS_DB.get(`pending_${token}`);
        if (!pendingData) {
          return htmlResponse(generateStatusHTML("Detection", "无效验证流：请勿直接访问，必须完成任务方可生效！", true));
        }
        const { hwid, currentStage, nextStage } = JSON.parse(pendingData);
        const now = Date.now();
        const startedAt = await env.KEYS_DB.get(`ad_start_${token}`);
        if (!startedAt) {
          const userAgent = request.headers.get("User-Agent") || "";
          const referer = request.headers.get("Referer") || "";
          const isFromAdNetwork = referer.includes("lootlink.io") || 
                                 referer.includes("linkvertise") || 
                                 referer.includes("work.ink");
          
          if (!isFromAdNetwork && !userAgent.includes("Mobile")) {
            return htmlResponse(generateStatusHTML("Security", "检测到直接访问！请通过广告页面完成验证。", true));
          }
        }
        
        await env.KEYS_DB.delete(`pending_${token}`);
        await env.KEYS_DB.delete(`ad_start_${token}`);
        await env.KEYS_DB.put(`stage_${hwid}`, nextStage.toString());
        await env.KEYS_DB.put(`completed_${hwid}_stage_${currentStage}`, "true", { expirationTtl: 86400 * 7 });
        if (nextStage < 3) {
          return htmlResponse(generateStageCompleteHTML(currentStage, nextStage, rootUrl, hwid));
        } else {
          const finalKey = "KEY-" + Math.random().toString(36).substring(2, 10).toUpperCase();
          await env.KEYS_DB.put(`active_key_${hwid}`, finalKey, { expirationTtl: 86400 });
          return htmlResponse(generateStatusHTML("Success", `恭喜完成所有阶段！卡密 24h 有效：<br><br><b style="color:#fff; font-size:24px;">${finalKey}</b>`, false));
        }
      }
      if (path === "/ad-start") {
        if (!token) return jsonResponse({ status: "error", msg: "Token缺失" }, 400);
        await env.KEYS_DB.put(`ad_start_${token}`, Date.now().toString(), { expirationTtl: 3600 });
        return jsonResponse({ status: "success" });
      }
      return htmlResponse("System Running. <a href='/admin' style='color:#333'>Admin</a>");
    } catch (e) {
      return htmlResponse(`<h2>500 Internal Error</h2><p>${e.message}</p>`);
    }
  }
};

const UI_STYLE = `
<style>
    :root {
        --glass: rgba(255, 255, 255, 0.04);
        --glass-border: rgba(255, 255, 255, 0.1);
        --btn-grey: rgba(200, 200, 200, 0.08);
    }
    body {
        margin: 0; padding: 0; background: #000; color: #fff;
        font-family: 'Inter', -apple-system, sans-serif;
        display: flex; justify-content: center; align-items: center; min-height: 100vh;
        background: radial-gradient(circle at 50% 0%, #111 0%, #000 100%);
        overflow: hidden;
    }
    .container {
        background: var(--glass);
        backdrop-filter: blur(35px) saturate(150%);
        -webkit-backdrop-filter: blur(35px) saturate(150%);
        border: 1px solid var(--glass-border);
        border-radius: 30px; padding: 40px; width: 380px;
        box-shadow: 0 40px 80px rgba(0,0,0,0.6);
        animation: fadeIn 0.8s cubic-bezier(0.16, 1, 0.3, 1);
    }
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
    }
    h2 { font-weight: 400; font-size: 22px; text-align: center; margin-bottom: 30px; letter-spacing: -0.5px; }
    .input-group { margin-bottom: 20px; }
    .label { font-size: 11px; color: #666; margin-bottom: 8px; margin-left: 5px; text-transform: uppercase; letter-spacing: 1.5px; display:block; }
    input, select {
        width: 100%; padding: 14px 18px; background: rgba(255, 255, 255, 0.03);
        border: 1px solid var(--glass-border); border-radius: 16px;
        color: #fff; font-size: 14px; box-sizing: border-box; outline: none; transition: 0.3s;
    }
    input:focus { border-color: rgba(255,255,255,0.3); background: rgba(255,255,255,0.06); }
    
    .custom-select { position: relative; width: 100%; cursor: pointer; }
    .select-trigger {
        padding: 14px 18px; background: rgba(255,255,255,0.05);
        border: 1px solid var(--glass-border); border-radius: 16px;
        display: flex; justify-content: space-between; align-items: center; font-size: 14px;
    }
    .options-list {
        position: absolute; top: 110%; left: 0; width: 100%;
        background: rgba(15, 15, 15, 0.95); backdrop-filter: blur(20px);
        border: 1px solid var(--glass-border); border-radius: 16px;
        max-height: 0; opacity: 0; overflow: hidden; z-index: 100; transition: 0.4s cubic-bezier(0.16, 1, 0.3, 1);
    }
    .custom-select.open .options-list { max-height: 250px; opacity: 1; padding: 5px 0; }
    .option { padding: 12px 18px; font-size: 14px; color: #888; transition: 0.3s; }
    .option:hover { background: rgba(255,255,255,0.1); color: #fff; }
    .panel-wrap { display: none; }
    .panel-wrap.active { display: block; animation: panelIn 0.5s; }
    @keyframes panelIn { from { opacity: 0; transform: scale(0.98); } to { opacity: 1; transform: scale(1); } }
    button, .btn {
        width: 100%; padding: 16px; background: var(--btn-grey);
        backdrop-filter: blur(15px); border: 1px solid rgba(255,255,255,0.1);
        border-radius: 18px; color: #fff; font-weight: 600; cursor: pointer; transition: 0.3s; 
        margin-top: 25px; display: block; text-align: center; text-decoration: none; box-sizing: border-box;
    }
    button:hover, .btn:hover { background: rgba(255,255,255,0.15); transform: translateY(-2px); }
    #toast {
        position: fixed; top: 25px; left: 50%; transform: translate(-50%, -100px);
        padding: 12px 30px; border-radius: 50px; background: #fff; color: #000;
        font-size: 14px; font-weight: 600; transition: 0.6s cubic-bezier(0.16, 1, 0.3, 1); z-index: 1000;
    }
    #toast.show { transform: translate(-50%, 0); }
    .stage-progress {
        display: flex; justify-content: space-between; margin-bottom: 25px; position: relative;
    }
    .stage-progress:before {
        content: ''; position: absolute; top: 50%; left: 10%; right: 10%; height: 2px; 
        background: rgba(255,255,255,0.1); transform: translateY(-50%); z-index: 1;
    }
    .stage-dot {
        width: 32px; height: 32px; border-radius: 50%; background: rgba(255,255,255,0.05);
        border: 1px solid rgba(255,255,255,0.1); display: flex; align-items: center;
        justify-content: center; font-size: 12px; color: #666; position: relative; z-index: 2;
    }
    .stage-dot.active {
        background: rgba(255,255,255,0.15); border-color: rgba(255,255,255,0.3); color: #fff;
    }
    .stage-dot.completed {
        background: rgba(0,255,0,0.1); border-color: rgba(0,255,0,0.3); color: #0f0;
    }
    .stage-label {
        position: absolute; bottom: -25px; left: 50%; transform: translateX(-50%);
        font-size: 10px; color: #666; white-space: nowrap;
    }
    
    .ad-warning {
        padding: 15px; background: rgba(255,100,100,0.1); border-radius: 12px;
        margin: 20px 0; border: 1px solid rgba(255,100,100,0.2);
        font-size: 13px; color: #ff6b6b;
    }
</style>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
`;

function generateAdminHTML(rootUrl, config) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Admin</title>${UI_STYLE}</head>
    <body>
        <div id="toast"></div>
        <div class="container">
            <h2>Admin Management</h2>
            <div class="input-group"><span class="label">Admin Password</span><input type="password" id="pw" placeholder="••••••••"></div>
            <div class="input-group"><span class="label">Static Key / Prefix</span><input type="text" id="sk" value="${config.secret_key}"></div>
            
            <div class="input-group">
                <span class="label">Key Mode</span>
                <select id="km" style="background:#111; color:#fff; border:1px solid var(--glass-border);">
                    <option value="static" ${config.key_mode==='static'?'selected':''}>Static (Fixed Key)</option>
                    <option value="random" ${config.key_mode==='random'?'selected':''}>Random (New Key / 24h)</option>
                </select>
            </div>

            <div class="input-group">
                <span class="label">Method</span>
                <div class="custom-select" id="cSelect" onclick="this.classList.toggle('open')">
                    <div class="select-trigger"><span id="sText">${config.provider_type}</span><i class="fas fa-chevron-down"></i></div>
                    <div class="options-list">
                        <div class="option" onclick="selectMode('work', 'Work (Custom)')">Work (Custom)</div>
                        <div class="option" onclick="selectMode('linkvertise', 'Linkvertise')">Linkvertise</div>
                        <div class="option" onclick="selectMode('lootlabs', 'LootLabs')">LootLabs</div>
                    </div>
                </div>
            </div>

            <div id="p-work" class="panel-wrap ${config.provider_type==='work'?'active':''}">
                <div class="input-group"><span class="label">Redirect URL</span><input type="text" id="work_url" value="${config.work_url}"></div>
            </div>
            <div id="p-linkvertise" class="panel-wrap ${config.provider_type==='linkvertise'?'active':''}">
                <div class="input-group"><span class="label">LV User ID</span><input type="text" id="lv_id" value="${config.lv_id}"></div>
                <div class="input-group"><span class="label">LV Secret Key</span><input type="password" id="lv_secret" value="${config.lv_secret}"></div>
            </div>
            <div id="p-lootlabs" class="panel-wrap ${config.provider_type==='lootlabs'?'active':''}">
                <div class="input-group"><span class="label">LootLabs Link</span><input type="text" id="ll_link" value="${config.ll_link}"></div>
                <div class="input-group"><span class="label">LL Secret Key</span><input type="password" id="ll_secret" value="${config.ll_secret}"></div>
            </div>

            <button onclick="save()">Apply Configuration</button>
            <p style="font-size:10px; color:#444; margin-top:20px; text-align:center;">
                LootLabs Destination URL 请填：<br>
                ${rootUrl}/callback<br><br>
                注意：LootLabs会自动重定向到/callback，系统已处理此情况<br>
                系统已启用三阶段验证：0-1-2-3，第3阶段免广告直接获取随机密钥
            </p>
        </div>
        <script>
            let mode = '${config.provider_type}';
            function selectMode(m, text) {
                mode = m; document.getElementById('sText').innerText = text;
                document.querySelectorAll('.panel-wrap').forEach(p => p.classList.remove('active'));
                document.getElementById('p-' + m).classList.add('active');
            }
            async function save() {
                const b = document.querySelector('button'); b.innerText = 'Syncing...';
                const payload = {
                    password: document.getElementById('pw').value,
                    secret_key: document.getElementById('sk').value,
                    key_mode: document.getElementById('km').value,
                    provider_type: mode,
                    work_url: document.getElementById('work_url').value,
                    lv_id: document.getElementById('lv_id').value,
                    lv_secret: document.getElementById('lv_secret').value,
                    ll_link: document.getElementById('ll_link').value,
                    ll_secret: document.getElementById('ll_secret').value
                };
                const res = await fetch('/save-config', { method: 'POST', body: JSON.stringify(payload) });
                const r = await res.json();
                const t = document.getElementById('toast');
                t.innerText = r.success ? 'Success: Saved' : 'Error: ' + r.msg;
                t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 3000);
                b.innerText = 'Apply Configuration';
            }
        </script>
    </body></html>`;
}

function generateStartVerifyHTML(adLink, currentStage, nextStage, rootUrl, hwid, token) {
  const stageNames = ["阶段 0", "阶段 1", "阶段 2", "阶段 3"];
  const adStartScript = token ? `
    <script>
      fetch('${rootUrl}/ad-start?token=${token}', { method: 'POST' });
      document.cookie = "ll_token=${token}; path=/; max-age=3600";
    </script>
  ` : '';
  
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>广告验证 - ${stageNames[nextStage]}</title>${UI_STYLE}</head><body>
    <div class="container" style="text-align:center">
        <h2>广告验证</h2>
        <div class="stage-progress">
            ${[0,1,2,3].map(i => `
                <div style="position:relative">
                    <div class="stage-dot ${i < currentStage ? 'completed' : (i === currentStage ? 'active' : '')}">
                        ${i < currentStage ? '<i class="fas fa-check"></i>' : i}
                    </div>
                    <div class="stage-label">${stageNames[i]}</div>
                </div>
            `).join('')}
        </div>
        
        <p>当前：${stageNames[currentStage]} → 进入 ${stageNames[nextStage]}<br>
           请点击下方按钮完成任务以继续。</p>
        
        <div class="ad-warning">
            <i class="fas fa-exclamation-triangle"></i> 
            注意：部分广告商（如LootLabs）会自动重定向到/callback<br>
            这是正常现象，系统会自动处理
        </div>
        
        <a href="${adLink}" id="adLink" class="btn">开始 ${stageNames[nextStage]} 广告验证</a>
        
        <p style="font-size:12px; color:#888; margin-top:20px;">
            <i class="fas fa-info-circle"></i> 完成广告后会自动返回并进入下一阶段
        </p>
        
        <div style="margin-top:20px; padding:15px; background:rgba(255,255,255,0.03); border-radius:12px;">
            <p style="font-size:12px; color:#aaa; margin:0;">
                <i class="fas fa-shield-alt"></i> 阶段验证保护已启用<br>
                确保按顺序完成所有阶段
            </p>
        </div>
    </div>
    ${adStartScript}
  </body></html>`;
}

function generateStageCompleteHTML(currentStage, nextStage, rootUrl, hwid) {
  const stageNames = ["阶段 0", "阶段 1", "阶段 2", "阶段 3"];
  
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>阶段完成</title>${UI_STYLE}</head><body>
    <div class="container" style="text-align:center">
        <h2>✅ 阶段完成</h2>

        <div class="stage-progress">
            ${[0,1,2,3].map(i => `
                <div style="position:relative">
                    <div class="stage-dot ${i < nextStage ? 'completed' : (i === nextStage ? 'active' : '')}">
                        ${i < nextStage ? '<i class="fas fa-check"></i>' : i}
                    </div>
                    <div class="stage-label">${stageNames[i]}</div>
                </div>
            `).join('')}
        </div>
        
        <p>恭喜！你已完成 <b style="color:#fff">${stageNames[currentStage]}</b><br>
           成功进入 <b style="color:#fff">${stageNames[nextStage]}</b><br><br>
           剩余阶段：${3 - nextStage} / 3</p>
        
        ${nextStage < 3 ? `
            <button class="btn" onclick="window.location.href='${rootUrl}/getlink?hwid=${hwid}'">
                继续 ${stageNames[nextStage]} 验证
            </button>
            <p style="font-size:12px; color:#888; margin-top:10px;">
                ${nextStage === 2 ? "下一阶段为最终阶段，完成后将直接获取卡密！" : "继续完成剩余阶段以获取卡密。"}
            </p>
        ` : `
            <button class="btn" onclick="window.location.href='${rootUrl}/getlink?hwid=${hwid}'">
                <i class="fas fa-key"></i> 获取卡密
            </button>
        `}
        
        <button class="btn" style="margin-top:15px; background:rgba(255,255,255,0.03);" onclick="window.close()">
            关闭页面
        </button>
    </div>
  </body></html>`;
}

function generateStatusHTML(title, msg, isError) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">${UI_STYLE}</head><body>
    <div class="container" style="text-align:center">
        <h2 style="${isError ? 'color:#ff4757' : 'color:#fff'}">${title}</h2>
        <p>${msg}</p>
        <button class="btn" style="border:none" onclick="window.close()">Close Page</button>
    </div>
  </body></html>`;
}