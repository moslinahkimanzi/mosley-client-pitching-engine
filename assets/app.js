(()=>{'use strict';
const $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state={csrf:'',user:null,leads:[],drafts:[],followups:[],proposals:[],metrics:{},gmail:null,billing:null,config:{search:false,ai:false},updates:null,feedback:[],maintenance:null,improvements:[],onboarding:null,preferences:null,regions:null,authMode:'login',pendingAuditReport:null};
function toast(msg,error=false){$('toast').textContent=msg;$('toast').className='notice'+(error?' error':'');}
function note(id,msg,error=false){$(id).textContent=msg;$(id).className='notice'+(error?' error':'');}
async function copyTextToClipboard(value,noticeId,successText){
 const text=String(value||'');if(!text.trim())return note(noticeId,'There is no text to copy yet.',true);
 try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(text);}else{throw new Error('Clipboard API unavailable');}note(noticeId,successText||'Copied to clipboard.');}
 catch(err){const area=document.createElement('textarea');area.value=text;area.setAttribute('readonly','');area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();let copied=false;try{copied=document.execCommand('copy');}catch{}area.remove();if(copied)note(noticeId,successText||'Copied to clipboard.');else note(noticeId,'Clipboard access was denied. Select the text and press Ctrl+C.',true);}
}
function cookie(name){const item=document.cookie.split('; ').find(x=>x.startsWith(name+'='));return item?decodeURIComponent(item.split('=').slice(1).join('=')):'';}
async function refreshCsrf(){const r=await fetch('/api/auth/csrf',{credentials:'same-origin'});if(!r.ok)throw new Error('Unable to initialise security token');const j=await r.json();state.csrf=j.csrf_token||cookie('mcas_csrf');}
async function api(path,opts={}){const method=(opts.method||'GET').toUpperCase();const headers={'Accept':'application/json',...(opts.headers||{})};if(opts.body!==undefined)headers['Content-Type']='application/json';if(['POST','PATCH','DELETE','PUT'].includes(method)){state.csrf=cookie('mcas_csrf')||state.csrf;headers['X-CSRF-Token']=state.csrf;}const r=await fetch(path,{...opts,method,headers,credentials:'same-origin'});const type=r.headers.get('content-type')||'';const data=type.includes('application/json')?await r.json():await r.text();if(!r.ok)throw new Error(data.detail||data.message||data||('Request failed ('+r.status+')'));return data;}
function showAuth(){ $('app').classList.add('hide');$('auth').classList.remove('hide');initGoogleSignIn().catch(err=>note('authNotice',err.message,true));}
function showApp(){ $('auth').classList.add('hide');$('app').classList.remove('hide');$('signedEmail').textContent=state.user.email||'';}
function applyTheme(theme){const chosen=theme==='system'?(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches?'light':'dark'):theme;document.body.dataset.theme=chosen==='light'?'light':'dark';}
if(window.matchMedia){window.matchMedia('(prefers-color-scheme: light)').addEventListener('change',()=>{if(state.preferences?.theme==='system')applyTheme('system');});}
const translations={en:{workspace_title:'My workspace',workspace_subtitle:'Set the region, currency, language, time zone and appearance for this workspace.',regional_heading:'Regional preferences',regional_help:'These settings belong to your account and affect prospect search, estimates and date/time display. Your workspace is not limited to the selected country.',country_label:'Workspace country / market',currency_label:'Display currency',timezone_label:'Time zone',timezone_help:'Automatically detected from this browser on first setup. You can change it manually.',language_label:'Language',theme_label:'Background theme',pricing_multiplier_label:'Local pricing adjustment',pricing_multiplier_help:'Planning adjustment only. This is not verified market-price research. Adjust it to your own pricing policy.',save_preferences:'Save workspace preferences',detect_timezone:'Detect my time zone',regional_research_heading:'How regional settings affect MCAS',region_search_label:'Prospect discovery',region_search_value:'Country and language parameters',region_pricing_label:'Website estimates',region_pricing_value:'Local multiplier and currency conversion',region_timezone_label:'Dates and reminders',region_timezone_value:'Your selected IANA time zone',region_disclaimer:'Currency rates are indicative. Country pricing multipliers are starting assumptions that you can edit; they are not verified quotations or market surveys.',nav_workspace:'My workspace'},sw:{workspace_title:'Nafasi yangu ya kazi',workspace_subtitle:'Weka nchi, sarafu, lugha, saa na mwonekano wa nafasi hii ya kazi.',regional_heading:'Mipangilio ya eneo',regional_help:'Mipangilio hii ni ya akaunti yako na huathiri utafiti wa wateja, makadirio na muda.',country_label:'Nchi / soko la nafasi ya kazi',currency_label:'Sarafu ya kuonyesha',timezone_label:'Saa za eneo',timezone_help:'Hugunduliwa kiotomatiki kutoka kwenye kivinjari mara ya kwanza. Unaweza kubadilisha.',language_label:'Lugha',theme_label:'Mandhari ya nyuma',pricing_multiplier_label:'Marekebisho ya bei za eneo',pricing_multiplier_help:'Ni marekebisho ya makadirio tu, si utafiti wa bei zilizothibitishwa.',save_preferences:'Hifadhi mipangilio',detect_timezone:'Tambua saa zangu',regional_research_heading:'Jinsi mipangilio ya eneo inavyoathiri MCAS',region_search_label:'Utafiti wa wateja',region_search_value:'Vigezo vya nchi na lugha',region_pricing_label:'Makadirio ya tovuti',region_pricing_value:'Kizidishi cha eneo na ubadilishaji wa sarafu',region_timezone_label:'Tarehe na vikumbusho',region_timezone_value:'Saa zako za IANA',region_disclaimer:'Viwango vya sarafu ni vya makadirio. Vigezo vya bei vinaweza kuhaririwa na si nukuu zilizothibitishwa.',nav_workspace:'Nafasi yangu'},fr:{workspace_title:'Mon espace de travail',workspace_subtitle:'Définissez le pays, la devise, la langue, le fuseau horaire et l’apparence.',regional_heading:'Préférences régionales',regional_help:'Ces paramètres appartiennent à votre compte et influencent la recherche, les estimations et les dates.',country_label:'Pays / marché',currency_label:'Devise d’affichage',timezone_label:'Fuseau horaire',timezone_help:'Détecté automatiquement depuis ce navigateur lors de la première configuration.',language_label:'Langue',theme_label:'Thème d’arrière-plan',pricing_multiplier_label:'Ajustement tarifaire local',pricing_multiplier_help:'Ajustement indicatif uniquement, pas une étude de marché vérifiée.',save_preferences:'Enregistrer les préférences',detect_timezone:'Détecter mon fuseau horaire',regional_research_heading:'Effet des paramètres régionaux',region_search_label:'Recherche de prospects',region_search_value:'Paramètres de pays et de langue',region_pricing_label:'Estimations de sites web',region_pricing_value:'Ajustement local et conversion de devise',region_timezone_label:'Dates et rappels',region_timezone_value:'Votre fuseau horaire IANA',region_disclaimer:'Les taux et ajustements sont indicatifs et modifiables.',nav_workspace:'Mon espace'},es:{workspace_title:'Mi espacio de trabajo',workspace_subtitle:'Configura la región, moneda, idioma, zona horaria y apariencia.',regional_heading:'Preferencias regionales',regional_help:'Estos ajustes pertenecen a tu cuenta e influyen en la búsqueda, las estimaciones y las fechas.',country_label:'País / mercado',currency_label:'Moneda de visualización',timezone_label:'Zona horaria',timezone_help:'Se detecta automáticamente desde este navegador en la configuración inicial.',language_label:'Idioma',theme_label:'Tema de fondo',pricing_multiplier_label:'Ajuste de precios local',pricing_multiplier_help:'Ajuste orientativo, no un estudio de mercado verificado.',save_preferences:'Guardar preferencias',detect_timezone:'Detectar mi zona horaria',regional_research_heading:'Cómo afectan los ajustes regionales a MCAS',region_search_label:'Búsqueda de prospectos',region_search_value:'Parámetros de país e idioma',region_pricing_label:'Estimaciones web',region_pricing_value:'Multiplicador local y conversión',region_timezone_label:'Fechas y recordatorios',region_timezone_value:'Tu zona horaria IANA',region_disclaimer:'Las tasas y los multiplicadores son orientativos y editables.',nav_workspace:'Mi espacio'},de:{workspace_title:'Mein Arbeitsbereich',workspace_subtitle:'Land, Währung, Sprache, Zeitzone und Erscheinungsbild festlegen.',regional_heading:'Regionale Einstellungen',regional_help:'Diese Einstellungen gehören zu deinem Konto und beeinflussen Recherche, Schätzungen und Zeitangaben.',country_label:'Land / Markt',currency_label:'Anzeigewährung',timezone_label:'Zeitzone',timezone_help:'Wird bei der ersten Einrichtung automatisch aus diesem Browser erkannt.',language_label:'Sprache',theme_label:'Hintergrunddesign',pricing_multiplier_label:'Lokale Preisanpassung',pricing_multiplier_help:'Nur eine Planungshilfe, keine verifizierte Marktstudie.',save_preferences:'Einstellungen speichern',detect_timezone:'Meine Zeitzone erkennen',regional_research_heading:'Auswirkungen regionaler Einstellungen',region_search_label:'Interessentenrecherche',region_search_value:'Landes- und Sprachparameter',region_pricing_label:'Website-Schätzungen',region_pricing_value:'Lokaler Faktor und Währungsumrechnung',region_timezone_label:'Termine und Erinnerungen',region_timezone_value:'Deine IANA-Zeitzone',region_disclaimer:'Kurse und Faktoren sind Richtwerte und bearbeitbar.',nav_workspace:'Arbeitsbereich'},pt:{workspace_title:'Meu espaço de trabalho',workspace_subtitle:'Defina país, moeda, idioma, fuso horário e aparência.',regional_heading:'Preferências regionais',regional_help:'Estas definições pertencem à sua conta e afetam pesquisas, estimativas e datas.',country_label:'País / mercado',currency_label:'Moeda de apresentação',timezone_label:'Fuso horário',timezone_help:'Detetado automaticamente neste navegador na configuração inicial.',language_label:'Idioma',theme_label:'Tema de fundo',pricing_multiplier_label:'Ajuste de preços local',pricing_multiplier_help:'Ajuste de planeamento, não uma pesquisa de mercado verificada.',save_preferences:'Guardar preferências',detect_timezone:'Detetar o meu fuso horário',regional_research_heading:'Como as definições regionais afetam o MCAS',region_search_label:'Pesquisa de potenciais clientes',region_search_value:'Parâmetros de país e idioma',region_pricing_label:'Estimativas de sites',region_pricing_value:'Multiplicador local e conversão',region_timezone_label:'Datas e lembretes',region_timezone_value:'O seu fuso horário IANA',region_disclaimer:'As taxas e os multiplicadores são indicativos e editáveis.',nav_workspace:'Meu espaço'},ar:{workspace_title:'مساحة العمل الخاصة بي',workspace_subtitle:'اختر البلد والعملة واللغة والمنطقة الزمنية والمظهر.',regional_heading:'التفضيلات الإقليمية',regional_help:'هذه الإعدادات تخص حسابك وتؤثر في البحث والتقديرات وعرض التاريخ والوقت.',country_label:'بلد مساحة العمل / السوق',currency_label:'عملة العرض',timezone_label:'المنطقة الزمنية',timezone_help:'يتم اكتشافها تلقائياً من هذا المتصفح عند الإعداد الأول.',language_label:'اللغة',theme_label:'مظهر الخلفية',pricing_multiplier_label:'تعديل الأسعار المحلي',pricing_multiplier_help:'تعديل تخطيطي فقط وليس دراسة سوق موثقة.',save_preferences:'حفظ التفضيلات',detect_timezone:'اكتشاف منطقتي الزمنية',regional_research_heading:'كيف تؤثر الإعدادات الإقليمية في MCAS',region_search_label:'البحث عن العملاء المحتملين',region_search_value:'إعدادات البلد واللغة',region_pricing_label:'تقديرات المواقع',region_pricing_value:'معامل محلي وتحويل العملة',region_timezone_label:'التواريخ والتذكيرات',region_timezone_value:'منطقتك الزمنية IANA',region_disclaimer:'أسعار الصرف والمعاملات تقديرية وقابلة للتعديل.',nav_workspace:'مساحة العمل'}};
const pageTranslations={
 en:{page_overview:'Overview',page_prospects:'Prospect workspace',page_research:'Opportunity intelligence',page_advisor:'Website advisor',page_email:'Email studio',page_replies:'Reply assistant',page_proposals:'Proposal builder',page_followups:'Follow-up manager',page_gmail:'Gmail drafts',page_updates:'Updates & feedback'},
 sw:{page_overview:'Muhtasari',page_prospects:'Nafasi ya wateja',page_research:'Ujasusi wa fursa',page_advisor:'Mshauri wa tovuti',page_email:'Studio ya barua pepe',page_replies:'Msaidizi wa majibu',page_proposals:'Mjenzi wa mapendekezo',page_followups:'Msimamizi wa ufuatiliaji',page_gmail:'Rasimu za Gmail',page_updates:'Sasisho na maoni'},
 fr:{page_overview:'Vue d’ensemble',page_prospects:'Espace prospects',page_research:'Intelligence commerciale',page_advisor:'Conseiller de site web',page_email:'Studio e-mail',page_replies:'Assistant de réponse',page_proposals:'Créateur de propositions',page_followups:'Gestion des suivis',page_gmail:'Brouillons Gmail',page_updates:'Mises à jour et avis'},
 es:{page_overview:'Resumen',page_prospects:'Espacio de prospectos',page_research:'Inteligencia de oportunidades',page_advisor:'Asesor web',page_email:'Estudio de correo',page_replies:'Asistente de respuestas',page_proposals:'Creador de propuestas',page_followups:'Gestor de seguimiento',page_gmail:'Borradores de Gmail',page_updates:'Novedades y comentarios'},
 de:{page_overview:'Übersicht',page_prospects:'Interessentenbereich',page_research:'Geschäftschancen-Analyse',page_advisor:'Website-Berater',page_email:'E-Mail-Studio',page_replies:'Antwortassistent',page_proposals:'Angebotserstellung',page_followups:'Nachverfolgung',page_gmail:'Gmail-Entwürfe',page_updates:'Updates und Feedback'},
 pt:{page_overview:'Visão geral',page_prospects:'Área de potenciais clientes',page_research:'Inteligência de oportunidades',page_advisor:'Consultor de sites',page_email:'Estúdio de e-mail',page_replies:'Assistente de respostas',page_proposals:'Criador de propostas',page_followups:'Gestor de acompanhamentos',page_gmail:'Rascunhos do Gmail',page_updates:'Atualizações e feedback'},
 ar:{page_overview:'نظرة عامة',page_prospects:'مساحة العملاء المحتملين',page_research:'ذكاء الفرص',page_advisor:'مستشار المواقع',page_email:'استوديو البريد',page_replies:'مساعد الردود',page_proposals:'منشئ العروض',page_followups:'إدارة المتابعة',page_gmail:'مسودات Gmail',page_updates:'التحديثات والملاحظات'}
};
const navTranslations={
 en:{nav_overview:'Overview',nav_prospects:'Prospects',nav_research:'Research',nav_advisor:'Website advisor',nav_email:'Email studio',nav_replies:'Reply assistant',nav_proposals:'Proposals',nav_followups:'Follow-ups',nav_updates:'Updates & feedback',nav_gmail:'Gmail drafts'},
 sw:{nav_overview:'Muhtasari',nav_prospects:'Wateja watarajiwa',nav_research:'Utafiti',nav_advisor:'Mshauri wa tovuti',nav_email:'Studio ya barua pepe',nav_replies:'Msaidizi wa majibu',nav_proposals:'Mapendekezo',nav_followups:'Ufuatiliaji',nav_updates:'Sasisho na maoni',nav_gmail:'Rasimu za Gmail'},
 fr:{nav_overview:'Vue d’ensemble',nav_prospects:'Prospects',nav_research:'Recherche',nav_advisor:'Conseiller de site web',nav_email:'Studio e-mail',nav_replies:'Assistant de réponse',nav_proposals:'Propositions',nav_followups:'Suivis',nav_updates:'Mises à jour et avis',nav_gmail:'Brouillons Gmail'},
 es:{nav_overview:'Resumen',nav_prospects:'Prospectos',nav_research:'Investigación',nav_advisor:'Asesor web',nav_email:'Estudio de correo',nav_replies:'Asistente de respuestas',nav_proposals:'Propuestas',nav_followups:'Seguimientos',nav_updates:'Novedades y comentarios',nav_gmail:'Borradores de Gmail'},
 de:{nav_overview:'Übersicht',nav_prospects:'Interessenten',nav_research:'Recherche',nav_advisor:'Website-Berater',nav_email:'E-Mail-Studio',nav_replies:'Antwortassistent',nav_proposals:'Angebote',nav_followups:'Nachverfolgung',nav_updates:'Updates und Feedback',nav_gmail:'Gmail-Entwürfe'},
 pt:{nav_overview:'Visão geral',nav_prospects:'Potenciais clientes',nav_research:'Pesquisa',nav_advisor:'Consultor de sites',nav_email:'Estúdio de e-mail',nav_replies:'Assistente de respostas',nav_proposals:'Propostas',nav_followups:'Acompanhamentos',nav_updates:'Atualizações e feedback',nav_gmail:'Rascunhos do Gmail'},
 ar:{nav_overview:'نظرة عامة',nav_prospects:'العملاء المحتملون',nav_research:'البحث',nav_advisor:'مستشار المواقع',nav_email:'استوديو البريد',nav_replies:'مساعد الردود',nav_proposals:'العروض',nav_followups:'المتابعات',nav_updates:'التحديثات والملاحظات',nav_gmail:'مسودات Gmail'}
};
function applyLanguage(code){const dict={...(navTranslations[code]||navTranslations.en),...(pageTranslations[code]||pageTranslations.en),...(translations[code]||translations.en)};document.documentElement.lang=code;document.documentElement.dir=code==='ar'?'rtl':'ltr';document.querySelectorAll('[data-i18n]').forEach(el=>{const key=el.dataset.i18n;if(dict[key])el.textContent=dict[key];});}
function page(name){const adminPages=new Set(['integrations','security','admin-maintenance']);if(adminPages.has(name)&&!state.user?.is_admin){toast('Settings are available to administrators only.',true);name='overview';}document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id===name));document.querySelectorAll('[data-page]').forEach(b=>b.classList.toggle('active',b.dataset.page===name));if(name==='prospects')renderLeads();if(name==='studio')renderDrafts();if(name==='followups')renderFollowups();if(name==='proposals')renderProposals();if(name==='updates'){loadUpdates();loadMyFeedback();}if(name==='admin-maintenance')loadAdminMaintenance();if(name==='workspace-settings')renderWorkspaceSettings();if(name==='billing')renderBilling();}
document.querySelectorAll('[data-page]').forEach(b=>b.addEventListener('click',()=>page(b.dataset.page)));
document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>page(b.dataset.go)));
async function initGoogleSignIn(){
 const container=$('googleSignInButton');if(!container)return;
 const config=await api('/api/auth/google/config');
 if(!config.configured){container.innerHTML='';note('authNotice','Google sign-in is not configured. Set GOOGLE_CLIENT_ID in the server .env file and restart MCAS.',true);return;}
 if(!window.google?.accounts?.id){await new Promise((resolve,reject)=>{const start=Date.now(),timer=setInterval(()=>{if(window.google?.accounts?.id){clearInterval(timer);resolve();}else if(Date.now()-start>12000){clearInterval(timer);reject(new Error('Google Identity Services did not load. Check your network and Content Security Policy.'));}},100);});}
 const nonce=await api('/api/auth/google/nonce');
 container.innerHTML='';
 window.google.accounts.id.initialize({client_id:config.client_id,nonce:nonce.nonce,callback:async response=>{
  try{if(!response.credential)throw new Error('Google did not return an ID token.');await refreshCsrf();const result=await api('/api/auth/google',{method:'POST',body:JSON.stringify({credential:response.credential,nonce:nonce.nonce})});state.user=result;showApp();await loadAll();}
  catch(err){if(state.user){toast('Signed in, but workspace initialisation needs attention: '+err.message,true);}else{note('authNotice',err.message,true);setTimeout(()=>initGoogleSignIn().catch(()=>{}),500);}}
 }});
 window.google.accounts.id.renderButton(container,{type:'standard',theme:'outline',size:'large',text:'continue_with',shape:'rectangular',logo_alignment:'left',width:340});
}
$('logoutBtn').addEventListener('click',async()=>{try{await api('/api/auth/logout',{method:'POST'});state.user=null;await refreshCsrf();showAuth();}catch(e){toast(e.message,true);}});
async function boot(){try{await refreshCsrf();state.user=await api('/api/auth/me');showApp();await loadAll();}catch(e){showAuth();}}
async function loadAll(){try{const values=await Promise.all([api('/api/leads'),api('/api/drafts'),api('/api/followups'),api('/api/proposals'),api('/api/metrics'),api('/api/integrations/gmail/status'),api('/api/billing/status'),api('/api/integrations/status'),api('/api/auth/me'),api('/api/updates'),api('/api/feedback'),api('/api/onboarding'),api('/api/workspace/preferences'),api('/api/regions')]);[state.leads,state.drafts,state.followups,state.proposals,state.metrics,state.gmail,state.billing,state.config,state.user,state.updates,state.feedback,state.onboarding,state.preferences,state.regions]=values;$('settingsNavGroup').classList.toggle('hide',!state.user.is_admin);if(state.preferences.timezone==='auto'){const detected=Intl.DateTimeFormat().resolvedOptions().timeZone||'UTC';state.preferences.timezone=detected;try{state.preferences=await api('/api/workspace/preferences',{method:'PUT',body:JSON.stringify(state.preferences)});}catch{}}applyTheme(state.preferences.theme);applyLanguage(state.preferences.language_code);$('researchRegionalNote').textContent='Searching in '+countryDisplay(state.preferences.country_code)+' ('+state.preferences.country_code+') using '+state.preferences.language_code.toUpperCase()+'. Change this under My workspace.';renderAll();renderUpdates();renderMyFeedback();$('searchBadge').textContent=state.config.web_search_configured?'Connected':'Needs API key';$('searchBadge').className='badge '+(state.config.web_search_configured?'green':'amber');$('aiBadge').textContent=state.config.ai_configured?'Connected':'Optional';$('aiBadge').className='badge '+(state.config.ai_configured?'green':'amber');$('researchConfig').textContent=state.config.web_search_configured?'Configured':'Set SERPER_API_KEY in .env and restart MCAS';$('aiConfig').textContent=state.config.ai_configured?'Configured':'Set AI_API_KEY in .env and restart MCAS';$('gmailBadge').textContent=state.gmail.connected?'Connected':state.gmail.configured?'Ready to connect':'Not configured';$('gmailDetails').textContent=state.gmail.capability||'Gmail drafts only.';$('gmailConnect').disabled=!state.gmail.configured||state.gmail.connected;$('gmailDisconnect').disabled=!state.gmail.connected;$('billingStatus').textContent=state.billing.message;const returnedOrder=new URLSearchParams(location.search).get('payment_return');if(returnedOrder){try{const returned=await api('/api/billing/return?order_id='+encodeURIComponent(returnedOrder));state.billing=await api('/api/billing/status');renderBilling();note('billingNotice',returned.message);history.replaceState({},'',location.pathname);}catch(error){note('billingNotice',error.message,true);}}}catch(e){toast(e.message,true);}}
function billingMethodAvailable(method){
 const data=state.billing;
 return !!(data?.billing_enabled && data?.payment_methods?.[method]?.available);
}
function renderBilling(){
 const data=state.billing;if(!data)return;
 $('billingPlan').textContent=data.plan==='free'?'Free':((data.plans?.[data.plan]?.name)||data.plan||'Free');
 $('billingMonthlyCredits').textContent=Number(data.monthly_credits||0).toLocaleString();
 $('billingPurchasedCredits').textContent=Number(data.purchased_credits||0).toLocaleString();
 $('billingTotalCredits').textContent=Number(data.total_credits||0).toLocaleString();
 $('billingPeriod').textContent=data.plan==='free'?(data.period_end?'Free allowance refreshes '+new Date(data.period_end).toLocaleDateString():'Free plan'):(data.period_end?'Paid through '+new Date(data.period_end).toLocaleDateString():'Paid plan period not active');
 const method=$('billingMethod')?.value||'mpesa';
 const methodAvailable=billingMethodAvailable(method);
 const price=plan=>{
  const cents=Number(plan.amount_usd_cents||0);
  const usd='USD '+(cents/100).toFixed(2);
  const rate=Number(data.mpesa_quote?.usd_kes_rate);
  return method==='mpesa'&&Number.isFinite(rate)&&rate>0?usd+' · approx. KES '+Math.round((cents/100)*rate).toLocaleString():usd;
 };
 $('billingPlanCards').innerHTML=Object.entries(data.plans||{}).map(([code,plan])=>'<article class="card"><h3>'+esc(plan.name)+'</h3><div class="metric">'+price(plan)+'/30 days</div><p>'+Number(plan.credits||0).toLocaleString()+' included credits</p><button class="primary" data-billing-type="subscription" data-billing-code="'+esc(code)+'" '+(!methodAvailable?'disabled':'')+'>Choose '+esc(plan.name)+'</button></article>').join('');
 $('billingCreditCards').innerHTML=Object.entries(data.credit_packs||{}).map(([code,pack])=>'<article class="card"><h3>'+esc(pack.name)+'</h3><div class="metric">'+price(pack)+'</div><p>'+Number(pack.credits||0).toLocaleString()+' prepaid credits</p><button data-billing-type="credits" data-billing-code="'+esc(code)+'" '+(!methodAvailable?'disabled':'')+'>Buy credits</button></article>').join('');
 $('billingOrders').innerHTML=(data.recent_orders||[]).map(order=>{
  const amount=order.amount_usd_cents!==null&&order.amount_usd_cents!==undefined?'USD '+(Number(order.amount_usd_cents)/100).toFixed(2)+' base · '+esc(order.provider_currency||order.currency||'USD')+' '+esc(order.provider_amount||''):'KES '+Number(order.amount_kes||0).toLocaleString();
  return '<div class="item"><div class="itemtop"><strong>'+esc(order.item_type)+' · '+esc(order.item_code)+'</strong><span class="badge '+(order.status==='paid'?'green':'amber')+'">'+esc(order.status)+'</span></div><p>'+amount+' · '+esc(order.created_at)+'</p></div>';
 }).join('')||'<div class="empty">No payment orders yet.</div>';
 const quote=data.mpesa_quote;
 const quoteText=quote?'M-Pesa reference rate: 1 USD = '+esc(quote.usd_kes_rate)+' KES (dated '+esc(quote.rate_date)+').':'M-Pesa is unavailable until a current, dated USD/KES rate is configured.';
 const noteText=quoteText+' Card payments are charged in USD; M-Pesa payments are charged in KES. Final provider amount is confirmed at checkout.';
 if($('billingPriceNote'))$('billingPriceNote').textContent=noteText;
 if($('billingStatus'))$('billingStatus').textContent=(data.message||'')+' '+quoteText;
 document.querySelectorAll('[data-billing-type]').forEach(button=>{button.disabled=!methodAvailable;});
}
async function startBillingCheckout(type,code){
 const method=$('billingMethod').value,phone=$('billingPhone').value.trim();
 if(method==='mpesa'&&!phone){note('billingNotice','Enter the M-Pesa phone number, including country code.',true);return;}
 const buttons=[...document.querySelectorAll('[data-billing-type]')];buttons.forEach(button=>button.disabled=true);
 try{
  const result=await api('/api/billing/checkout',{method:'POST',body:JSON.stringify({item_type:type,item_code:code,payment_method:method,phone_number:method==='mpesa'?phone:null})});
  note('billingNotice','Secure checkout created. You will be redirected to the payment provider. MCAS will activate value only after payment verification.');
  window.location.assign(result.checkout_url);
 }catch(error){note('billingNotice',error.message,true);buttons.forEach(button=>button.disabled=false);}
}
$('billingPlanCards').addEventListener('click',event=>{const button=event.target.closest('[data-billing-type]');if(button)startBillingCheckout(button.dataset.billingType,button.dataset.billingCode);});
$('billingCreditCards').addEventListener('click',event=>{const button=event.target.closest('[data-billing-type]');if(button)startBillingCheckout(button.dataset.billingType,button.dataset.billingCode);});

async function refreshBillingStatus(){
 try{state.billing=await api('/api/billing/status');renderBilling();note('billingNotice','Billing status refreshed. A checkout redirect alone does not confirm payment.');}
 catch(error){note('billingNotice',error.message,true);}
}
$('refreshBillingBtn').addEventListener('click',refreshBillingStatus);
$('billingMethod').addEventListener('change',renderBilling);

function renderAll(){renderMetrics();renderLeads();renderDrafts();renderFollowups();renderProposals();renderSelects();renderUpdates();renderMyFeedback();renderOnboarding();renderBilling();}
const regionalPriceDefaults={KE:1,US:2.4,CA:2.1,GB:2.15,AU:2.1,NZ:1.85,DE:2,FR:1.95,IE:2,NL:2,CH:2.5,SG:1.9,AE:1.85,ZA:1.25,NG:0.9,GH:0.85,IN:0.8,PK:0.7,PH:0.85,BR:1.1,MX:1.05,JP:2,KR:1.8};
function countryDisplay(code){try{return new Intl.DisplayNames([state.preferences?.language_code||'en'],{type:'region'}).of(code)||code;}catch{return code;}}
function localTimezone(){return Intl.DateTimeFormat().resolvedOptions().timeZone||'UTC';}
function renderWorkspaceSettings(){if(!state.regions||!state.preferences)return;const p=state.preferences;const country=$('prefCountry'),currency=$('prefCurrency'),timezone=$('prefTimezone'),language=$('prefLanguage');country.innerHTML=state.regions.countries.map(x=>'<option value=\"'+x.code+'\">'+esc(countryDisplay(x.code))+' ('+x.code+')</option>').join('');country.value=p.country_code;currency.innerHTML=state.regions.currencies.map(x=>'<option value=\"'+x+'\">'+x+'</option>').join('');currency.value=p.currency_code;timezone.innerHTML='<option value=\"auto\">Automatic (browser)</option>'+state.regions.timezones.map(x=>'<option value=\"'+esc(x)+'\">'+esc(x.replaceAll('_',' '))+'</option>').join('');timezone.value=p.timezone||'auto';language.innerHTML=state.regions.languages.map(x=>'<option value=\"'+x.code+'\">'+esc(x.name)+'</option>').join('');language.value=p.language_code;$('prefTheme').value=p.theme;$('prefMultiplier').value=Number(p.pricing_multiplier||1).toFixed(2);applyLanguage(p.language_code);}
function currentPreferenceForm(){return {country_code:$('prefCountry').value,currency_code:$('prefCurrency').value,timezone:$('prefTimezone').value,language_code:$('prefLanguage').value,theme:$('prefTheme').value,pricing_multiplier:Number($('prefMultiplier').value)};}
async function saveWorkspacePreferences(){try{const prefs=currentPreferenceForm();if(!Number.isFinite(prefs.pricing_multiplier)||prefs.pricing_multiplier<0.5||prefs.pricing_multiplier>5)throw new Error('Pricing adjustment must be between 0.5 and 5.0.');if(prefs.timezone==='auto')prefs.timezone=localTimezone();state.preferences=await api('/api/workspace/preferences',{method:'PUT',body:JSON.stringify(prefs)});applyTheme(state.preferences.theme);applyLanguage(state.preferences.language_code);$('researchRegionalNote').textContent='Searching in '+countryDisplay(state.preferences.country_code)+' ('+state.preferences.country_code+') using '+state.preferences.language_code.toUpperCase()+'. Change this under My workspace.';note('workspacePreferencesNotice','Workspace preferences saved.');}catch(e){note('workspacePreferencesNotice',e.message,true);}}
$('prefCountry').addEventListener('change',()=>{const selected=state.regions.countries.find(x=>x.code===$('prefCountry').value);if(selected)$('prefCurrency').value=selected.currency;$('prefMultiplier').value=(regionalPriceDefaults[$('prefCountry').value]||1).toFixed(2);});
$('prefTheme').addEventListener('change',()=>applyTheme($('prefTheme').value));$('prefLanguage').addEventListener('change',()=>applyLanguage($('prefLanguage').value));$('saveWorkspacePreferences').addEventListener('click',saveWorkspacePreferences);$('detectTimezone').addEventListener('click',()=>{$('prefTimezone').value=localTimezone();note('workspacePreferencesNotice','Detected time zone: '+localTimezone()+'. Save to apply it.');});

function feedbackStatusLabel(value){return ({received:'Received',reviewing:'Under review',planned:'Planned',in_progress:'In progress',completed:'Completed',declined:'Not planned'})[value]||value;}
function renderUpdates(){
 const data=state.updates;if(!data)return;
 $('currentVersion').textContent='v'+data.current_version;$('latestVersion').textContent='v'+data.latest_version;
 $('updateAvailability').textContent=data.update_available?'A centrally managed update is available':'Current version';
 $('updateAvailability').className='metricnote';
 $('updateMessage').textContent=data.message||'Release information loaded.';
 $('releaseList').innerHTML=(data.releases||[]).map(item=>'<div class="item"><div class="itemtop"><strong>v'+esc(item.version)+' · '+esc(item.title)+'</strong><span class="badge green">Release notes</span></div><p>'+esc(item.summary)+'</p><ul>'+((item.changes||[]).map(change=>'<li>'+esc(change)+'</li>').join(''))+'</ul></div>').join('')||'<div class="empty">No release notes have been published.</div>';
}
function renderMyFeedback(){
 const items=state.feedback||[];$('myFeedbackCount').textContent=items.length;
 $('myFeedbackList').innerHTML=items.map(item=>'<div class="item"><div class="itemtop"><strong>'+esc(item.title)+'</strong><span class="badge">'+esc(feedbackStatusLabel(item.status))+'</span></div><p>'+esc(item.category)+' · Submitted '+esc(item.created_at)+'</p><p>'+esc(item.message)+'</p>'+(item.admin_note?'<div class="good"><b>MCAS team note:</b> '+esc(item.admin_note)+'</div>':'')+'</div>').join('')||'<div class="empty">You have not submitted feedback yet.</div>';
}
async function loadUpdates(){
 try{state.updates=await api('/api/updates');renderUpdates();}
 catch(e){note('feedbackNotice','Could not refresh release information: '+e.message,true);}
}
async function loadMyFeedback(){
 try{state.feedback=await api('/api/feedback');renderMyFeedback();}
 catch(e){note('feedbackNotice','Could not load your feedback history: '+e.message,true);}
}
$('refreshUpdatesBtn').addEventListener('click',async()=>{
 $('refreshUpdatesBtn').disabled=true;
 await loadUpdates();await loadMyFeedback();
 $('refreshUpdatesBtn').disabled=false;
});
$('feedbackForm').addEventListener('submit',async e=>{
 e.preventDefault();const btn=$('feedbackSubmit');btn.disabled=true;
 try{
  await api('/api/feedback',{method:'POST',body:JSON.stringify({category:$('feedbackCategory').value,title:$('feedbackTitle').value.trim(),message:$('feedbackMessage').value.trim(),ai_analysis_consent:$('feedbackAiConsent').checked})});
  $('feedbackForm').reset();note('feedbackNotice','Thank you. Your feedback has been submitted for review.');
  await loadMyFeedback();
 }catch(err){note('feedbackNotice',err.message,true);}
 finally{btn.disabled=false;}
});
async function loadAdminMaintenance(){
 if(!state.user?.is_admin){return note('adminFeedbackNotice','Administrator access is not enabled for this account.',true);}
 try{state.maintenance=await api('/api/admin/maintenance');renderAdminMaintenance();await loadImprovementReviews();}
 catch(e){note('adminFeedbackNotice','Maintenance dashboard could not be loaded: '+e.message,true);}
}
async function loadImprovementReviews(){
 try{state.improvements=await api('/api/admin/improvements');renderImprovementReviews();}
 catch(e){note('improvementAnalysisNotice','Could not load saved improvement reviews: '+e.message,true);}
}
function renderImprovementReviews(){
 const items=state.improvements||[];
 $('improvementReviewList').innerHTML=items.map(review=>
  '<div class="item"><div class="itemtop"><strong>AI review · '+esc(review.feedback_count)+' feedback item(s)</strong><span class="badge">Human review required</span></div>'+
  '<p>'+esc(review.created_at)+'</p><p>'+esc(review.summary)+'</p>'+
  (review.recommendations||[]).map(item=>
   '<div class="item"><div class="itemtop"><strong>'+esc(item.title)+'</strong><span class="badge">'+esc(item.priority)+' priority</span></div>'+
   '<p><b>Area:</b> '+esc(item.area)+'</p><p><b>Problem:</b> '+esc(item.problem)+'</p>'+
   '<p><b>Suggested change:</b> '+esc(item.suggested_change)+'</p>'+
   '<p><b>Test ideas:</b> '+(item.test_ideas||[]).map(esc).join(' · ')+'</p></div>'
  ).join('')+'</div>'
 ).join('')||'<div class="empty">No AI improvement reviews have been created yet.</div>';
}
function renderAdminMaintenance(){
 const data=state.maintenance;if(!data)return;
 $('adminFeedbackTotal').textContent=data.feedback_total;
 $('adminFeedbackOptedIn').textContent=data.feedback_opted_in_total||0;
 const open=Number(data.feedback_by_status?.received||0)+Number(data.feedback_by_status?.reviewing||0);
 $('adminFeedbackOpen').textContent=open;$('adminCurrentVersion').textContent='v'+data.current_version;
 $('maintenanceControls').innerHTML=(data.maintenance_controls||[]).map(control=>{
  const statusLabel={configured:'Configured',not_implemented:'Not implemented',external_action:'External action required',manual:'Manual approval'}[control.status]||control.status;
  const badge=control.status==='configured'?'green':control.status==='not_implemented'?'red':'amber';
  return '<div class="item"><div class="itemtop"><strong>'+esc(control.name)+'</strong><span class="badge '+badge+'">'+esc(statusLabel)+'</span></div><p>'+esc(control.detail)+'</p></div>';
 }).join('');
 $('improvementRecommendations').innerHTML=(data.recommendations||[]).map(item=>'<div class="item"><div class="itemtop"><strong>'+esc(item.area)+'</strong><span class="badge">'+esc(item.count)+' report(s)</span></div><p>'+esc(item.action)+'</p></div>').join('')||'<div class="empty">No feedback themes yet. Customer submissions will help identify improvement priorities.</div>';
 $('automationBoundary').textContent=data.automation_boundary+' '+data.workflow_status_source;
 $('adminFeedbackList').innerHTML=(data.feedback||[]).map(item=>'<div class="item" data-feedback-card="'+esc(item.id)+'"><div class="itemtop"><strong>'+esc(item.title)+'</strong><span class="badge">'+esc(feedbackStatusLabel(item.status))+'</span></div><p>'+esc(item.category)+' · '+esc(item.customer_email)+' · '+esc(item.created_at)+'</p><p>'+esc(item.message)+'</p><div class="field"><label>Review status</label><select data-feedback-status><option value="received" '+(item.status==='received'?'selected':'')+'>Received</option><option value="reviewing" '+(item.status==='reviewing'?'selected':'')+'>Under review</option><option value="planned" '+(item.status==='planned'?'selected':'')+'>Planned</option><option value="in_progress" '+(item.status==='in_progress'?'selected':'')+'>In progress</option><option value="completed" '+(item.status==='completed'?'selected':'')+'>Completed</option><option value="declined" '+(item.status==='declined'?'selected':'')+'>Not planned</option></select></div><div class="field"><label>Reply / internal note (visible to this customer)</label><textarea data-feedback-note maxlength="1000">'+esc(item.admin_note||'')+'</textarea></div><button data-feedback-save="'+esc(item.id)+'" class="primary">Save review</button></div>').join('')||'<div class="empty">No customer feedback has been submitted.</div>';
}
$('refreshMaintenanceBtn').addEventListener('click',loadAdminMaintenance);
$('runTestLabChecks').addEventListener('click',async()=>{const b=$('runTestLabChecks');b.disabled=true;$('testLabChecksResult').innerHTML='<div class="empty">Running synthetic checks…</div>';try{const d=await api('/api/admin/test-lab/run',{method:'POST',body:JSON.stringify({})});$('testLabChecksResult').innerHTML='<div class="good">'+esc(d.passed)+'/'+esc(d.total)+' checks passed. No production data modified.</div>'+d.results.map(x=>'<div class="item"><div class="itemtop"><strong>'+esc(x.scenario)+'</strong><span class="badge '+(x.passed?'green':'red')+'">'+(x.passed?'PASS':'FAIL')+'</span></div><p>Expected '+esc(x.expected)+' · Actual '+esc(x.actual)+'</p></div>').join('');}catch(e){$('testLabChecksResult').innerHTML='<div class="warning">'+esc(e.message)+'</div>';}finally{b.disabled=false;}});
$('generateTestLabPlan').addEventListener('click',async()=>{const feature=$('testLabFeature').value.trim();if(feature.length<8)return note('testLabPlanNotice','Describe the feature first.',true);const b=$('generateTestLabPlan');b.disabled=true;note('testLabPlanNotice','Generating QA test plan…');try{const p=await api('/api/admin/test-lab/plan',{method:'POST',body:JSON.stringify({feature})});$('testLabPlanResult').innerHTML='<div class="item"><h3>'+esc(p.summary)+'</h3><h3>Risks</h3><ul>'+p.risks.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul><h3>Acceptance criteria</h3><ul>'+p.acceptance_criteria.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul><h3>Test cases</h3>'+p.test_cases.map(t=>'<div class="item"><div class="itemtop"><strong>'+esc(t.id)+' · '+esc(t.title)+'</strong><span class="badge">'+esc(t.priority)+'</span></div><ol>'+t.steps.map(v=>'<li>'+esc(v)+'</li>').join('')+'</ol><p><b>Expected:</b> '+esc(t.expected_result)+'</p></div>').join('')+'<div class="warning">'+esc(p.execution_boundary)+'</div></div>';note('testLabPlanNotice','AI test plan generated. These are proposed tests, not passed results.');}catch(e){note('testLabPlanNotice',e.message,true);}finally{b.disabled=false;}});
$('runTestLabAudit').addEventListener('click',async()=>{const url=$('testLabAuditUrl').value.trim();if(!url){$('testLabAuditResult').innerHTML='<div class="warning">Enter a public URL to audit.</div>';return;}const b=$('runTestLabAudit');b.disabled=true;$('testLabAuditResult').innerHTML='<div class="empty">Auditing without creating a prospect…</div>';try{const d=await api('/api/admin/test-lab/audit',{method:'POST',body:JSON.stringify({url,max_pages:Number($('testLabAuditPages').value)})});renderAuditResult($('testLabAuditResult'),d);}catch(e){$('testLabAuditResult').innerHTML='<div class="warning">'+esc(e.message)+'</div>';}finally{b.disabled=false;}});
$('runImprovementAnalysisBtn').addEventListener('click',async()=>{
 const button=$('runImprovementAnalysisBtn');button.disabled=true;button.textContent='Analysing feedback…';
 try{
  const result=await api('/api/admin/improvements/analyze',{method:'POST'});
  note('improvementAnalysisNotice','Analysis complete: '+result.feedback_count+' opted-in feedback item(s) reviewed. The proposal is saved; no code was changed or deployed.');
  await loadImprovementReviews();
 }catch(err){note('improvementAnalysisNotice',err.message,true);}
 finally{button.disabled=false;button.textContent='Analyse opted-in feedback';}
});
$('adminFeedbackList').addEventListener('click',async e=>{
 const button=e.target.closest('[data-feedback-save]');if(!button)return;
 const card=button.closest('[data-feedback-card]');if(!card)return;
 button.disabled=true;
 try{
  await api('/api/admin/feedback/'+encodeURIComponent(button.dataset.feedbackSave),{method:'PATCH',body:JSON.stringify({status:card.querySelector('[data-feedback-status]').value,admin_note:card.querySelector('[data-feedback-note]').value})});
  note('adminFeedbackNotice','Feedback review saved. The customer can see the updated status and note.');
  await loadAdminMaintenance();
 }catch(err){note('adminFeedbackNotice',err.message,true);}
 finally{button.disabled=false;}
});


function renderOnboarding(){
 const data=state.onboarding;if(!data)return;
 $('onboardingProgress').value=Number(data.percent)||0;
 $('onboardingProgressLabel').textContent=(data.completed||0)+' of '+(data.total||0)+' key steps complete';
 const makeStep=(step)=>'<div class="item"><div class="itemtop"><div><strong>'+(step.completed?'✓ ':'')+esc(step.title)+'</strong><p>'+esc(step.description)+'</p></div><span class="badge '+(step.completed?'green':'amber')+'">'+(step.completed?'Complete':'Next step')+'</span></div><div class="itemactions"><button type="button" '+(step.completed?'':'class="primary" ')+'data-onboarding-target="'+esc(step.target)+'">'+(step.completed?'Open':'Continue')+'</button></div></div>';
 $('onboardingSteps').innerHTML=(data.steps||[]).map(makeStep).join('')||'<div class="empty">Your setup steps will appear here.</div>';
 $('onboardingOptionalSteps').innerHTML=(data.optional_steps||[]).map(step=>'<div class="item"><div class="itemtop"><div><strong>'+esc(step.title)+'</strong><p>'+esc(step.description)+'</p></div><span class="badge '+(step.completed?'green':'')+'">'+(step.completed?'Connected':'Optional')+'</span></div><div class="itemactions"><button type="button" data-onboarding-target="'+esc(step.target)+'">'+(step.completed?'Manage':'Set up')+'</button></div></div>').join('');
 $('onboardingPrivacyNote').textContent=data.privacy_note||'Progress is based on your own workspace.';
}
$('onboardingCard').addEventListener('click',e=>{
 const button=e.target.closest('[data-onboarding-target]');if(!button)return;
 const target=button.dataset.onboardingTarget;
 if(target)page(target);
});

function renderMetrics(){const m=state.metrics;$('mLeads').textContent=m.leads||0;$('mVerified').textContent=m.verified||0;$('mDrafts').textContent=m.pending_approval||0;$('mFollow').textContent=m.open_followups||0;$('pUnverified').textContent=state.leads.filter(l=>l.status==='Unverified').length;$('pPending').textContent=m.pending_approval||0;$('pDnc').textContent=m.do_not_contact||0;
$('recentLeads').innerHTML=state.leads.slice(0,5).map(l=>'<div class="row"><span><b>'+esc(l.name)+'</b><br><span class="tiny">'+esc(l.market||'')+'</span></span><span class="badge">'+esc(l.status)+'</span></div>').join('')||'<div class="empty">No prospects yet. Add your first lead.</div>';}
function renderSelects(){
 const options=state.leads.map(l=>'<option value="'+esc(l.id)+'">'+esc(l.name)+'</option>').join('');
 ['emailLead','replyLead','proposalLead','followLead','advisorLead','advancedAuditLead','competitorLead'].forEach(id=>{
  const el=$(id);if(!el)return;
  const old=el.value;
  el.innerHTML='<option value="">'+(state.leads.length?'Select a saved prospect…':'No saved prospects — add one in Prospects')+'</option>'+options;
  if(old&&state.leads.some(l=>l.id===old))el.value=old;
 });
 renderAdvisorProspectPicker();
 if($('advisorLead')&&$('advisorLead').value)updateAdvisorProspect();
}
function renderAdvisorProspectPicker(){
 const select=$('advisorLead'),trigger=$('advisorLeadPickerButton'),label=$('advisorLeadPickerLabel'),options=$('advisorLeadOptions');
 if(!select||!trigger||!label||!options)return;
 const leads=Array.isArray(state.leads)?state.leads:[];
 const selected=leads.find(l=>String(l.id)===String(select.value));
 trigger.disabled=leads.length===0;
 label.textContent=selected?selected.name+' — '+(selected.market||'Location not recorded'):(leads.length?'Choose a saved prospect ('+leads.length+')':'No saved prospects — add one in Prospects');
 const query=($('advisorLeadSearch')?.value||'').trim().toLowerCase();
 const filtered=leads.filter(l=>[l.name,l.market,l.status,l.website,l.evidence,l.contact_email].join(' ').toLowerCase().includes(query));
 options.innerHTML=filtered.map(l=>'<button type="button" class="advisor-prospect-option" role="option" aria-selected="'+(selected&&String(selected.id)===String(l.id)?'true':'false')+'" data-advisor-prospect-id="'+esc(l.id)+'"><span class="advisor-prospect-option-name">'+esc(l.name)+'</span><span class="advisor-prospect-option-meta">'+esc(l.market||'Location not recorded')+' · '+esc(l.status||'Unverified')+'</span></button>').join('')||'<div class="advisor-prospect-empty">'+(leads.length?'No prospects match your search.':'No saved prospects are available in this workspace yet.')+'</div>';
}
function closeAdvisorProspectPicker(){
 const menu=$('advisorLeadPickerMenu'),trigger=$('advisorLeadPickerButton');
 if(menu)menu.classList.add('hide');
 if(trigger)trigger.setAttribute('aria-expanded','false');
}
function openAdvisorProspectPicker(){
 const menu=$('advisorLeadPickerMenu'),trigger=$('advisorLeadPickerButton'),search=$('advisorLeadSearch');
 if(!menu||!trigger||trigger.disabled)return;
 menu.classList.remove('hide');trigger.setAttribute('aria-expanded','true');
 if(search)search.value='';
 renderAdvisorProspectPicker();
 if(search)search.focus();
}
function websiteCategoryLabel(l){return ({not_listed:'No website link found (unconfirmed)',verified:'Website verified · public response observed',broken:'Website returned an HTTP error',restricted:'Automated check restricted',needs_check:'Website needs checking',not_checked:'Not yet checked'})[l.website_status]||'Website status unknown';}
function renderLeads(){
 const q=($('leadFilter')?.value||'').toLowerCase(),st=$('leadFilterStatus')?.value||'',ws=$('leadWebsiteFilter')?.value||'';
 const items=state.leads.filter(l=>(!st||l.status===st)&&(!ws||l.website_status===ws)&&[l.name,l.market,l.evidence,l.contact_email,l.website,l.business_address].join(' ').toLowerCase().includes(q));
 $('leadList').innerHTML=items.map(l=>{
  let proof={};try{proof=JSON.parse(l.business_verification_json||'{}');}catch{}
  const businessStatus=l.business_verification_status||'unverified';
  const businessLabel=businessStatus==='human_confirmed'?'HUMAN CONFIRMED':businessStatus==='provider_reconfirmed'?'LISTING MATCHED · REVIEW REQUIRED':businessStatus==='needs_manual_review'?'IDENTITY NEEDS REVIEW':'UNVERIFIED';
  const businessClass=businessStatus==='human_confirmed'?'green':businessStatus==='provider_reconfirmed'?'amber':'red';
  const listing=proof.listing||{};
  const checks=proof.checks||{};
  const sourceHtml=(proof.independent_sources||[]).map(s=>'<p>Independent source: <a href="'+safeLink(s.url)+'" target="_blank" rel="noopener noreferrer">'+esc(s.title||s.domain)+'</a> · '+esc(s.domain||'')+'<br>'+esc(s.snippet||'')+'</p>').join('');
  const proofHtml=proof.checked_at?'<div class="item"><b>Fresh public-listing check</b><p>'+esc(proof.checked_at)+' · Name match: '+(checks.business_name_match?'yes':'no')+' · Address match: '+(checks.address_match?'yes':'no')+' · Phone match: '+(checks.phone_match?'yes':'no')+' · Independent source: '+(checks.independent_web_source?'yes':'no')+'</p><p>'+esc(listing.name||'')+' · '+esc(listing.address||'')+' · '+esc(listing.phone||'')+'</p>'+(listing.website?'<p>Candidate website: <a href="'+safeLink(listing.website)+'" target="_blank" rel="noopener noreferrer">'+esc(listing.website)+'</a></p>':'')+(listing.source_url?'<p>Listing: <a href="'+safeLink(listing.source_url)+'" target="_blank" rel="noopener noreferrer">Open public listing</a></p>':'')+sourceHtml+'<p class="tiny">'+esc(proof.limitation||'')+'</p></div>':'';
  const confirm=businessStatus==='provider_reconfirmed'?'<button class="primary" data-confirm-business="'+esc(l.id)+'">I reviewed this listing — confirm business</button>':'';
  return '<div class="item"><div class="itemtop"><strong>'+esc(l.name)+'</strong><span class="badge '+(l.do_not_contact?'red':l.status==='Won'?'green':'')+'">'+esc(l.do_not_contact?'DO NOT CONTACT':l.status)+'</span></div><p>'+esc(l.market||'')+' · '+esc(l.business_address||'Address not confirmed')+' · '+esc(l.website||'No website URL recorded')+'</p><p><span class="badge '+businessClass+'">'+businessLabel+'</span> <span class="badge '+(l.website_status==='verified'?'green':l.website_status==='broken'?'red':l.website_status==='not_listed'?'amber':'')+'">'+esc(websiteCategoryLabel(l))+'</span>'+(l.business_verified_at?' · <span class="tiny">Human confirmed '+esc(l.business_verified_at)+'</span>':'')+(l.website_verified_at?' · <span class="tiny">Website checked '+esc(l.website_verified_at)+'</span>':'')+'</p><p>'+esc(l.evidence||'No evidence recorded.')+'</p><p>'+esc(l.contact_email||'No contact email')+' · '+esc(l.contact_phone||'No phone number')+(l.source_url?' · <a href="'+safeLink(l.source_url)+'" target="_blank" rel="noopener noreferrer">Discovery source</a>':'')+'</p>'+proofHtml+'<div class="itemactions"><button data-recheck-business="'+esc(l.id)+'">Recheck business identity</button>'+confirm+'<button data-verify-website="'+esc(l.id)+'" '+(!l.website?'disabled':'')+'>Verify website</button>'+(l.status!=='Won'?'<button data-win="'+esc(l.id)+'">Client accepted</button>':'<span class="badge green">Client accepted</span>')+(l.status==='Won'?'<button class="primary" data-builder-prompt="'+esc(l.id)+'">Generate AI-builder prompt</button>':'')+'<button data-dnc="'+esc(l.id)+'">'+(l.do_not_contact?'Remove DNC':'Do not contact')+'</button><button class="danger" data-delete-lead="'+esc(l.id)+'">Delete</button></div></div>';
 }).join('')||'<div class="empty">No prospects match this filter.</div>';
 renderSelects();
}
function safeLink(raw){try{const u=new URL(raw,location.origin);return ['http:','https:'].includes(u.protocol)?esc(u.href):'#';}catch{return '#';}}
function renderDrafts(){$('draftList').innerHTML=state.drafts.map(d=>{const gmailAction=d.gmail_draft_id?'<span class="badge green">IN GMAIL DRAFTS</span>':(state.gmail?.connected&&d.to_email?'<button class="primary" data-gmail="'+esc(d.id)+'">Create Gmail draft</button>':'');const reportBadge=d.audit_report_id?'<span class="badge green">AUDIT PDF ATTACHED</span>':'';return '<div class="item"><div class="itemtop"><strong>'+esc(d.subject)+'</strong><span class="badge amber">PENDING APPROVAL</span></div><p>'+esc(d.kind)+' · '+esc(d.to_email||'No recipient')+' · '+esc(d.created_at||'')+'</p>'+(reportBadge?'<p>'+reportBadge+' <span class="tiny">PDF will be attached when you create the Gmail draft.</span></p>':'')+'<p>'+esc(d.body.slice(0,260))+(d.body.length>260?'…':'')+'</p><div class="itemactions">'+gmailAction+'<button data-copy-draft="'+esc(d.id)+'">Copy email</button><button class="danger" data-delete-draft="'+esc(d.id)+'">Delete</button></div></div>';}).join('')||'<div class="empty">No drafts saved yet.</div>';}
function formatWorkspaceDate(value){if(!value)return 'No due date';try{return new Intl.DateTimeFormat(state.preferences?.language_code||'en',{dateStyle:'medium',timeStyle:'short',timeZone:state.preferences?.timezone||localTimezone()}).format(new Date(value));}catch{return value;}}
function zonedDateTimeToIso(value,zone){if(!value)return null;const parts=value.split('T');if(parts.length!==2)return null;const [y,m,d]=parts[0].split('-').map(Number),[hh,mm]=parts[1].split(':').map(Number);if(![y,m,d,hh,mm].every(Number.isFinite))return null;const desired=Date.UTC(y,m-1,d,hh,mm);let guess=desired;for(let i=0;i<4;i++){const p=new Intl.DateTimeFormat('en-CA',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date(guess));const v={};p.forEach(x=>{v[x.type]=x.value;});const observed=Date.UTC(Number(v.year),Number(v.month)-1,Number(v.day),Number(v.hour),Number(v.minute));guess+=desired-observed;}return new Date(guess).toISOString();}
function renderFollowups(){$('followList').innerHTML=state.followups.map(f=>'<div class="item"><div class="itemtop"><strong>'+esc(f.title)+'</strong><span class="badge">'+esc(f.state)+'</span></div><p>'+esc(f.lead_name)+' · '+esc(formatWorkspaceDate(f.due_at))+'</p><p>'+esc(f.notes)+'</p>'+(f.state==='open'?'<div class="itemactions"><button data-follow-done="'+esc(f.id)+'">Mark complete</button></div>':'')+'</div>').join('')||'<div class="empty">No follow-up tasks yet.</div>';const noteEl=$('followTimezoneNote');if(noteEl)noteEl.textContent='Times are interpreted and displayed in '+(state.preferences?.timezone||localTimezone())+'.';}
function renderProposals(){$('proposalList').innerHTML=state.proposals.map(p=>'<div class="item"><div class="itemtop"><strong>'+esc(p.title)+'</strong><span class="badge">'+esc(p.state)+'</span></div><p>'+esc(p.content.slice(0,300))+'…</p></div>').join('')||'<div class="empty">No proposals saved yet.</div>';}
$('leadFilter').addEventListener('input',renderLeads);$('leadFilterStatus').addEventListener('change',renderLeads);$('leadWebsiteFilter').addEventListener('change',renderLeads);
$('leadForm').addEventListener('submit',async e=>{e.preventDefault();const data={name:$('leadName').value.trim(),website:$('leadWebsite').value.trim()||null,market:$('leadMarket').value.trim(),contact_email:$('leadEmail').value.trim()||null,contact_phone:$('leadPhone').value.trim()||null,source_url:$('leadSource').value.trim()||null,evidence:$('leadEvidence').value.trim(),status:$('leadStatus').value,do_not_contact:$('leadDnc').checked};try{await api('/api/leads',{method:'POST',body:JSON.stringify(data)});e.target.reset();$('leadMarket').value='Kenya';await loadAll();note('leadNotice','Prospect saved to your private workspace.');}catch(err){note('leadNotice',err.message,true);}});
$('leadList').addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;if(b.dataset.recheckBusiness){b.disabled=true;try{const result=await api('/api/leads/'+encodeURIComponent(b.dataset.recheckBusiness)+'/verify-business',{method:'POST'});await loadAll();toast(result.status==='provider_reconfirmed'?'A matching public listing was found. Review the name, address, phone and source before confirming.':'No sufficiently strong match was found. This prospect remains unverified.',result.status!=='provider_reconfirmed');}catch(err){toast(err.message,true);}finally{b.disabled=false;}return;}if(b.dataset.confirmBusiness){if(!confirm('Have you personally reviewed the fresh public listing and confirmed that it refers to this business? This does not verify legal registration or ownership of the contact details.'))return;b.disabled=true;try{const result=await api('/api/leads/'+encodeURIComponent(b.dataset.confirmBusiness)+'/confirm-business',{method:'POST'});await loadAll();toast(result.message||'Business confirmation saved.');}catch(err){toast(err.message,true);}finally{b.disabled=false;}return;}if(b.dataset.builderPrompt){try{note('builderPromptNotice','Generating website-builder prompt…');const d=await api('/api/leads/'+encodeURIComponent(b.dataset.builderPrompt)+'/builder-prompt',{method:'POST'});$('builderPromptText').value=d.prompt;$('builderPromptPanel').classList.remove('hide');note('builderPromptNotice',d.note);$('builderPromptPanel').scrollIntoView({behavior:'smooth',block:'nearest'});}catch(err){note('builderPromptNotice',err.message,true);}return;}if(b.dataset.verifyWebsite){b.disabled=true;try{const result=await api('/api/leads/'+encodeURIComponent(b.dataset.verifyWebsite)+'/verify-website',{method:'POST'});await loadAll();toast(result.message||'Website status updated.');}catch(err){toast(err.message,true);}finally{b.disabled=false;}return;}const id=b.dataset.verify||b.dataset.win||b.dataset.dnc||b.dataset.deleteLead;if(!id)return;const l=state.leads.find(x=>x.id===id);if(!l)return;try{if(b.dataset.deleteLead){if(!confirm('Delete this prospect and related follow-up tasks?'))return;await api('/api/leads/'+encodeURIComponent(id),{method:'DELETE'});}else{const payload={name:l.name,website:l.website,market:l.market,evidence:l.evidence,status:b.dataset.win?'Won':b.dataset.verify?'Verified':l.status,contact_email:l.contact_email,contact_phone:l.contact_phone,source_url:l.source_url,business_address:l.business_address,do_not_contact:b.dataset.dnc?!l.do_not_contact:!!l.do_not_contact};await api('/api/leads/'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(payload)});}await loadAll();}catch(err){toast(err.message,true);}});

function websiteStateText(value){
 const labels={not_listed:"No website returned (not confirmed)",broken:"Listed website returned an error",needs_improvement:"Limited technical issues detected",working:"Website responded and basic checks passed",access_restricted:"Website blocked the check",needs_review:"Website could not be safely verified"};
 return labels[value]||"Needs manual verification";
}
$('startResearchBtn').addEventListener('click',async()=>{
 const location=$('researchLocation').value.trim();
 if(!location)return note('researchRunNotice','Enter a town, city or named administrative area first.',true);
 const btn=$('startResearchBtn');btn.disabled=true;
 $('researchRunResults').innerHTML='<div class="empty">Research is running. MCAS is searching Serper Places and checking any listed public websites. This may take a moment.</div>';
 note('researchRunNotice','Starting your research run…');
 try{
  const d=await api('/api/research/run',{method:'POST',body:JSON.stringify({
   location,industry:$('researchIndustry').value,keywords:$('researchKeywords').value.trim(),
   max_results:Number($('researchLimit').value)
  })});
  $('researchRunResults').innerHTML=d.results.map(x=>{
   const label=websiteStateText(x.website_state);
   const scoreLine=Number.isFinite(Number(x.opportunity_score))?'<p><b>Opportunity priority:</b> '+esc(x.opportunity_score)+'/100 <span class="tiny">(evidence-based sorting, not buying intent)</span></p>':'';
   const audit=x.website_audit?'<p><b>Quick check:</b> HTTP '+esc(x.website_audit.http_status??"unknown")+' · mobile viewport: '+esc(x.website_audit.has_viewport_meta===true?"detected":x.website_audit.has_viewport_meta===false?"not detected":"not checked")+' · meta description: '+esc(x.website_audit.has_meta_description===true?"detected":x.website_audit.has_meta_description===false?"not detected":"not checked")+' · H1: '+esc(x.website_audit.has_h1===true?"detected":x.website_audit.has_h1===false?"not detected":"not checked")+'</p>':'';
   const reasons=(x.score_reasons||[]).length?'<p class="tiny">Priority signals: '+esc(x.score_reasons.join("; "))+'</p>':'';
   const source='<a href="'+safeLink(x.source_url)+'" target="_blank" rel="noopener noreferrer">Serper / Google Maps result</a>';
   const website=x.website?'<p>Website: <a href="'+safeLink(x.website)+'" target="_blank" rel="noopener noreferrer">'+esc(x.website)+'</a></p>':'<p>Serper did not return an official website link. Verify independently.</p>';
   const contactEmail=x.contact_email?'<a href="mailto:'+esc(x.contact_email)+'">'+esc(x.contact_email)+'</a>':'No public email listed';
   const contactPhone=x.contact_phone?'<a href="tel:'+encodeURIComponent(x.contact_phone)+'">'+esc(x.contact_phone)+'</a>':'No public phone listed';
   const contact='<p><b>Public address:</b> '+esc(x.business_address||'Not supplied by provider')+'</p><p><b>Public contact:</b> '+contactEmail+' · '+contactPhone+'</p><p class="tiny">Business identity: UNVERIFIED — review and recheck in Prospects. No proposal or outreach draft is generated before confirmation.</p>';
   const pages=(x.pages||[]).map(v=>'<li>'+esc(v)+'</li>').join('');
   const delivery=x.duplicate?'Already saved in your CRM; review its existing verification evidence.':'Saved as UNVERIFIED. Recheck business identity in Prospects and inspect the supporting sources. Proposals and outreach drafts are withheld until you confirm the business.';
   return '<div class="item"><div class="itemtop"><strong>'+esc(x.name)+'</strong><span class="badge '+(x.website_state==='broken'||x.website_state==='needs_improvement'?'amber':'')+'">'+esc(label)+'</span></div>'+scoreLine+reasons+website+contact+audit+'<p>'+esc(x.evidence||'No additional evidence returned.')+'</p><p><b>Recommended:</b> '+esc(x.recommendation||'Manual review')+'</p><ul>'+pages+'</ul><p>'+source+'</p><p class="tiny">'+delivery+'</p></div>';
  }).join('')||'<div class="empty">No matching business records were found. Try a nearby administrative area or a broader category.</div>';
  const summary=d.summary||{};note('researchRunNotice','Research finished in '+(d.resolved_location||d.location)+'. '+d.saved+' new prospects saved; '+d.results.length+' records reviewed. Highest priority score: '+(summary.highest_opportunity_score??'—')+'/100. '+d.attribution+' '+d.warning);
  await loadAll();
 }catch(e){$('researchRunResults').innerHTML='<div class="empty">No research results were saved. '+esc(e.message)+'</div>';note('researchRunNotice',e.message,true);}
 finally{btn.disabled=false;}
});
$('copyBuilderPrompt').addEventListener('click',async()=>{try{await navigator.clipboard.writeText($('builderPromptText').value);note('builderPromptNotice','Prompt copied. Paste it into your chosen AI website builder.');}catch(e){$('builderPromptText').select();note('builderPromptNotice','Select and copy the prompt manually.');}});
$('searchBtn').addEventListener('click',async()=>{const q=$('researchQuery').value.trim();if(!q)return note('researchNotice','Enter a search query.',true);$('searchBtn').disabled=true;note('researchNotice','Searching public web results…');try{const d=await api('/api/research/search?q='+encodeURIComponent(q));$('researchResults').innerHTML=d.results.map(x=>'<div class="item"><strong>'+esc(x.title||'Untitled result')+'</strong><p>'+esc(x.description||'')+'</p><p><a href="'+safeLink(x.url)+'" target="_blank" rel="noopener noreferrer">'+esc(x.url)+'</a></p><div class="itemactions"><button data-save-result="'+esc(encodeURIComponent(JSON.stringify(x)))+'">Save as prospect</button></div></div>').join('')||'<div class="empty">No results returned.</div>';note('researchNotice',d.warning);}catch(e){note('researchNotice',e.message,true);}finally{$('searchBtn').disabled=false;}});
$('researchResults').addEventListener('click',async e=>{const b=e.target.closest('[data-save-result]');if(!b)return;try{const x=JSON.parse(decodeURIComponent(b.dataset.saveResult));const host=new URL(x.url).hostname;await api('/api/leads',{method:'POST',body:JSON.stringify({name:x.title||host,website:null,market:'Unspecified',evidence:'Discovered in search result: '+(x.description||'Description not supplied')+'. Verify the business identity, website and claims before outreach.',source_url:x.url,status:'Unverified'})});await loadAll();note('researchNotice','Saved as an unverified prospect. Please check the source before contacting.');}catch(e){note('researchNotice','Could not save this result: '+e.message,true);}});
function renderAuditResult(host,data){const findings=(data.findings||[]).map(f=>'<div class="item"><div class="itemtop"><strong>'+esc(f.title)+'</strong><span class="badge '+(f.severity==='high'?'red':f.severity==='medium'?'amber':'')+'">'+esc(f.severity)+'</span></div><p>'+esc(f.description)+'</p><p><b>Fix:</b> '+esc(f.recommendation)+'</p><p class="tiny">'+esc(f.url||'')+(f.evidence?' · '+esc(f.evidence):'')+'</p></div>').join('');host.innerHTML='<div class="item"><div class="itemtop"><strong>Audit summary</strong><span class="badge green">'+esc(data.pages_checked)+' page(s) checked</span></div><div class="metric">Health score '+esc(data.summary?.health_score??'—')+'/100</div><p>'+esc(data.summary?.high||0)+' high · '+esc(data.summary?.medium||0)+' medium · '+esc(data.summary?.low||0)+' low findings</p><p class="tiny">Checked '+esc(data.checked_at||'')+' · '+esc(data.elapsed_ms||0)+' ms · bounded public audit</p></div>'+findings+'<div class="warning">'+esc(data.scope_note||'This is not a penetration test or certification.')+'</div>';}

function renderAdvancedAuditResult(host,data){
 const s=data.summary||{},labels={detected_defect:'Detected defects',potential_risk:'Potential risks',recommendation:'Recommendations',unverified_observation:'Unverified observations'};
 const order=['detected_defect','potential_risk','recommendation','unverified_observation'];
 const groups=order.map(kind=>{const items=(data.findings||[]).filter(f=>f.classification===kind);if(!items.length)return '';const cards=items.map(f=>{const pages=(f.affected_pages||[f.url].filter(Boolean)).map(u=>'<li><a href="'+safeLink(u)+'" target="_blank" rel="noopener noreferrer">'+esc(u)+'</a></li>').join('');const evidence=(f.evidence_by_page||[]).map(e=>'<li>'+esc(e.url||'')+(e.detail?' — '+esc(e.detail):'')+'</li>').join('');return '<div class="item"><div class="itemtop"><strong>'+esc(f.title)+'</strong><span class="badge '+(f.severity==='high'?'red':f.severity==='medium'?'amber':'')+'">'+esc(f.severity||'info')+' · '+esc(f.code||'')+'</span></div><p>'+esc(f.description||'')+'</p><p><b>Recommended action:</b> '+esc(f.recommendation||'Review with the website owner.')+'</p><p class="tiny">'+esc(f.page_count??(f.affected_pages||[]).length)+' affected page(s)</p>'+(pages?'<details><summary>Affected pages</summary><ul>'+pages+'</ul></details>':'')+(evidence?'<details><summary>Evidence per page</summary><ul>'+evidence+'</ul></details>':'')+'</div>';}).join('');return '<h3>'+esc(labels[kind])+' ('+items.length+')</h3>'+cards;}).join('');
 const recs=(data.recommendations||[]).map(r=>'<div class="item"><div class="itemtop"><strong>'+esc(r.title)+'</strong><span class="badge">'+esc(r.priority||'review')+'</span></div><p>'+esc(r.description||'')+'</p><ul>'+(r.recommended_scope||[]).map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul><p class="tiny">'+esc(r.basis||'Suggested opportunity based on this audit.')+'</p></div>').join('');
 const canDownload=!!data.report_id;
 host.innerHTML='<div class="item"><div class="itemtop"><strong>Audit summary</strong><span class="badge green">'+esc(data.pages_checked||0)+' page(s) checked</span></div><div class="metric">Health score '+esc(s.health_score??'—')+'/100</div><p>'+esc(s.detected_defects??0)+' detected defects · '+esc(s.potential_risks??0)+' potential risks · '+esc(s.unverified_observations??0)+' unverified observations</p><p>'+esc(s.high||0)+' high · '+esc(s.medium||0)+' medium · '+esc(s.low||0)+' low · '+esc(s.info||0)+' informational</p><p class="tiny">'+esc(s.unique_findings??s.total??0)+' unique findings · '+esc(s.page_occurrences??0)+' page occurrences. Duplicate issue codes are counted once in the health score.</p><p class="tiny">Checked '+esc(data.checked_at||'')+' · '+esc(data.elapsed_ms||0)+' ms</p>'+(canDownload?'<div class="actions"><button class="primary" data-audit-download="'+esc(data.report_id)+'">Download client PDF</button><button data-attach-audit="'+esc(data.report_id)+'" data-audit-lead="'+esc(data.lead_id||'')+'">Attach PDF to an email draft</button></div>':'<p class="tiny">This result has no saved report identifier, so it cannot be downloaded or attached.</p>')+'</div>'+(groups||'<div class="empty">No findings were detected by this bounded check.</div>')+'<h3>Website improvement opportunities</h3>'+(recs||'<div class="empty">No mapped improvement recommendations were generated.</div>')+'<div class="warning">'+esc(data.score_disclaimer||'The score is a prioritisation indicator, not a security certification.')+' '+esc(data.scope_note||'This is not a penetration test or certification.')+'</div>';
}
$('advancedAuditLead').addEventListener('change',()=>{
 const lead=selectedLead($('advancedAuditLead').value);
 if(lead?.website)$('advancedAuditUrl').value=lead.website;
});
$('runAdvancedAudit').addEventListener('click',async()=>{
 const url=$('advancedAuditUrl').value.trim(),leadId=$('advancedAuditLead').value||null;
 if(!url)return note('advancedAuditNotice','Enter a public website URL.',true);
 const btn=$('runAdvancedAudit');btn.disabled=true;$('advancedAuditResult').innerHTML='<div class="empty">Running bounded public website audit…</div>';
 try{
  const data=await api('/api/audit-website',{method:'POST',body:JSON.stringify({url,lead_id:leadId,max_pages:Number($('advancedAuditPages').value||10)})});
  renderAdvancedAuditResult($('advancedAuditResult'),data);
  note('advancedAuditNotice','Audit complete. Findings are observations for manual review, not confirmed vulnerabilities.');
  if(leadId)await loadAll();
 }catch(e){$('advancedAuditResult').innerHTML='<div class="warning">'+esc(e.message)+'</div>';note('advancedAuditNotice',e.message,true);}
 finally{btn.disabled=false;}
});
$('advancedAuditResult').addEventListener('click',async e=>{
 const download=e.target.closest('[data-audit-download]'),attach=e.target.closest('[data-attach-audit]'),remove=e.target.closest('[data-remove-audit-report]');
 if(download){const id=download.dataset.auditDownload;download.disabled=true;try{const response=await fetch('/api/audit-reports/'+encodeURIComponent(id)+'/pdf',{credentials:'same-origin',headers:{'Accept':'application/pdf'}});if(!response.ok){const type=response.headers.get('content-type')||'';let message='PDF download failed ('+response.status+').';if(type.includes('application/json')){const body=await response.json();message=body.detail||message;}throw new Error(message);}const blob=await response.blob(),disposition=response.headers.get('content-disposition')||'',match=disposition.match(/filename="?([^";]+)"?/i),filename=match?match[1]:'mcas-website-audit.pdf',url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);note('advancedAuditNotice','Client PDF downloaded. Review it before sharing.');}catch(err){note('advancedAuditNotice',err.message,true);}finally{download.disabled=false;}return;}
 if(attach){const id=attach.dataset.attachAudit,leadId=attach.dataset.auditLead||null;state.pendingAuditReport={id,leadId};if(leadId){const lead=selectedLead(leadId);if(lead){$('emailLead').value=leadId;if(lead.contact_email)$('emailTo').value=lead.contact_email;}}$('emailReportAttachment').innerHTML='Selected audit report: <b>'+esc(id)+'</b> <button type="button" data-remove-audit-report>Remove</button>. Save the email draft, then create it in Gmail to include the PDF.';$('studio').scrollIntoView({behavior:'smooth',block:'start'});note('emailNotice','Audit PDF selected. Save your email as a pending draft to attach it.');return;}
 if(remove){state.pendingAuditReport=null;$('emailReportAttachment').textContent='No audit PDF selected.';return;}
});
$('runCompetitorIntel').addEventListener('click',async()=>{
 const btn=$('runCompetitorIntel'),leadId=$('competitorLead').value;
 if(!leadId)return note('competitorNotice','Select a saved prospect first.',true);
 btn.disabled=true;$('competitorResult').innerHTML='<div class="empty">Searching public business listings and checking candidate websites…</div>';
 try{
  const data=await api('/api/competitor-intelligence',{method:'POST',body:JSON.stringify({lead_id:leadId,industry:$('competitorIndustry').value,max_results:Number($('competitorLimit').value||5)})});
  const summary=data.comparison||{},target=data.target||{},targetAudit=target.audit_summary||{};
  const cards=(data.competitors||[]).map(item=>'<div class="item"><div class="itemtop"><strong>'+esc(item.name)+'</strong><span class="badge">'+esc(item.website_state||'not checked')+'</span></div><p>'+esc(item.category||'Category not supplied')+' · '+esc(item.address||'Address unavailable')+'</p><p>Website: '+(item.website?'<a href="'+safeLink(item.website)+'" target="_blank" rel="noopener noreferrer">'+esc(item.website)+'</a>':'No website listed by provider')+'</p><p>Provider rating: '+esc(item.rating??'Not listed')+' ('+esc(item.rating_count??0)+' reviews shown)</p>'+(item.audit_summary?'<p>Static audit: '+esc(item.audit_summary.health_score??'—')+'/100 · '+esc(item.audit_summary.findings??0)+' findings</p>':'')+'<p><a href="'+safeLink(item.source_url||'')+'" target="_blank" rel="noopener noreferrer">View discovery source</a></p></div>').join('');
  $('competitorResult').innerHTML='<div class="good"><b>'+esc(summary.competitors_found||0)+' candidate businesses found</b><p>Target: '+esc(target.name||'')+' · Website state: '+esc(target.website_state||'not listed')+(targetAudit.health_score!==undefined?' · Static audit '+esc(targetAudit.health_score)+'/100':'')+'</p><p>Listed websites: '+esc(summary.with_listed_websites||0)+' · No website listed: '+esc(summary.without_listed_websites||0)+' · Responding: '+esc(summary.responding_websites||0)+'</p></div>'+(cards||'<div class="empty">No candidate businesses were returned. Try another category or check Serper configuration.</div>')+'<div class="warning">'+(data.limitations||[]).map(esc).join('<br>')+'</div>';
  note('competitorNotice','Research complete. Results are unverified candidates; confirm details independently.');
 }catch(e){$('competitorResult').innerHTML='<div class="warning">'+esc(e.message)+'</div>';note('competitorNotice',e.message,true);}
 finally{btn.disabled=false;}
});

function selectedLead(id){return state.leads.find(l=>l.id===id);}
function emailText(l){const name=l.name,evidence=(l.evidence||'').trim(),checked=evidence&&!/not checked|unknown|not verified|not yet verified/i.test(evidence),service=$('service').value.trim()||'professional, mobile-friendly websites';const evidenceLine=checked?'I noted this from the information available: '+evidence+' I have not treated this as a full audit.':'I came across your public business listing while researching '+(l.market||'your area')+'. I have not confirmed a specific website problem, so I do not want to make assumptions.';return 'Hello '+name+' team,\n\n'+evidenceLine+'\n\nI help businesses make it easier for customers to understand their services and get in touch through '+service+'. A practical starting point could be clear service information, a mobile-friendly layout and a simple enquiry path, shaped around what your team actually needs.\n\nWould a brief 10–15 minute conversation next week be useful? I can share a few relevant ideas first, with no obligation.\n\nBest regards,\n'+$('signature').value.trim()+'\n\nIf you would prefer not to receive another message from me, just reply and I will not contact you again.';}
$('genEmail').addEventListener('click',()=>{const l=selectedLead($('emailLead').value);if(!l)return note('emailNotice','Add a prospect first.',true);if(l.do_not_contact)return note('emailNotice','This prospect is marked do-not-contact. Outreach is blocked.',true);$('emailTo').value=l.contact_email||'';$('emailSubject').value='A website idea for '+l.name;$('emailBody').value=emailText(l);note('emailNotice','Draft generated from your recorded evidence. Verify before use.');});
async function aiDraft(task){const l=selectedLead(task==='reply'?$('replyLead').value:task==='proposal'?$('proposalLead').value:$('emailLead').value);if(!l)return note(task==='reply'?'replyNotice':task==='proposal'?'proposalNotice':'emailNotice','Select a prospect first.',true);if(l.do_not_contact&&task!=='reply')return note(task==='proposal'?'proposalNotice':'emailNotice','Prospect is marked do-not-contact; outreach draft blocked.',true);try{const incoming=task==='reply'?$('incoming').value.trim():'';const service=task==='reply'?$('replyService').value:$('service').value;const d=await api('/api/assistant/draft',{method:'POST',body:JSON.stringify({lead_id:l.id,task,prospect_name:l.name,market:l.market||'',service:service||'website services',evidence:l.evidence||'',incoming})});if(task==='email'){const match=d.draft.match(/^Subject:\s*(.+?)(?:\r?\n){1,2}(?:Body:\s*)?/i);if(match){$('emailSubject').value=match[1].trim();$('emailBody').value=d.draft.slice(match[0].length).trim();}else{$('emailBody').value=d.draft;$('emailSubject').value='A website idea for '+l.name;}note('emailNotice',d.warning);}if(task==='reply'){$('replyBody').value=d.draft;note('replyNotice','AI reply generated. Review and edit it, then choose Save edited reply as new draft. Nothing was saved or sent automatically.');}if(task==='proposal'){$('proposalContent').value=d.draft;note('proposalNotice',d.warning);}}catch(e){note(task==='reply'?'replyNotice':task==='proposal'?'proposalNotice':'emailNotice',e.message,true);}}
$('aiEmail').addEventListener('click',()=>aiDraft('email'));$('aiProposal').addEventListener('click',()=>aiDraft('proposal'));
async function saveDraft(kind,subject,body,to,leadId,noteId,auditReportId=null){try{await api('/api/drafts',{method:'POST',body:JSON.stringify({kind,subject,body,to_email:to||null,lead_id:leadId||null,audit_report_id:auditReportId||null})});if(auditReportId&&state.pendingAuditReport?.id===auditReportId){state.pendingAuditReport=null;$('emailReportAttachment').textContent='No audit PDF selected.';}await loadAll();note(noteId,auditReportId?'Saved as pending approval with the audit PDF attached. Create a Gmail draft to attach the PDF. No email was sent.':'Saved as pending approval. No email was sent.');}catch(e){note(noteId,e.message,true);}}
$('copyEmail').addEventListener('click',()=>copyTextToClipboard('Subject: '+$('emailSubject').value+'\n\n'+$('emailBody').value,'emailNotice','Email copied to clipboard.'));
$('copyReply').addEventListener('click',()=>copyTextToClipboard($('replyBody').value,'replyNotice','Reply copied to clipboard.'));
$('saveEmail').addEventListener('click',()=>{const id=$('emailLead').value;const l=selectedLead(id);if(l?.do_not_contact)return note('emailNotice','Do-not-contact is active; cannot save an outreach email.',true);if(!$('emailBody').value.trim())return note('emailNotice','Write a message first.',true);const report=state.pendingAuditReport;if(report?.leadId&&report.leadId!==id)return note('emailNotice','The selected audit report is linked to a different prospect. Select that prospect or remove the report.',true);saveDraft('Cold email',$('emailSubject').value||'Website enquiry',$('emailBody').value,$('emailTo').value,id,'emailNotice',report?.id||null);});
$('genReply').addEventListener('click',()=>aiDraft('reply'));
$('saveReply').addEventListener('click',()=>{if(!$('replyBody').value.trim())return note('replyNotice','Generate a reply first.',true);saveDraft('Client reply','Reply draft',$('replyBody').value,$('replyTo').value,$('replyLead').value,'replyNotice');});
$('genProposal').addEventListener('click',()=>{const l=selectedLead($('proposalLead').value);if(!l)return note('proposalNotice','Add a prospect first.',true);const title=$('proposalTitle').value||'Website project proposal for '+l.name;$('proposalTitle').value=title;$('proposalContent').value='PROJECT PROPOSAL\n'+title+'\n\nPrepared for: '+l.name+'\nMarket: '+(l.market||'Not specified')+'\n\n1. CURRENT CONTEXT\n'+(l.evidence||'The client requirements and current website condition must be confirmed before scope is finalised.')+'\n\n2. PROPOSED APPROACH\n• Discovery and confirmation of business goals\n• Information architecture and page structure\n• Responsive design and implementation\n• Contact / enquiry flow and essential integrations\n• Quality assurance, handover and launch support\n\n3. DELIVERABLES\nList the agreed pages, features, integrations, content responsibilities and handover items here.\n\n4. TIMELINE\n'+($('proposalTimeline').value||'To be agreed after scope confirmation')+'\n\n5. INVESTMENT\n'+($('proposalBudget').value||'Quotation to be confirmed after scope')+'\n\n6. ASSUMPTIONS AND EXCLUSIONS\nConfirm hosting, domain, third-party subscriptions, copywriting, maintenance and change requests in writing.\n\n7. NEXT STEPS\nApprove the final scope and written quotation before work begins.\n\nPrepared by: '+$('signature').value;note('proposalNotice','Editable proposal structure generated. Confirm scope and pricing before sharing.');});
$('saveProposal').addEventListener('click',async()=>{const l=selectedLead($('proposalLead').value);if(!$('proposalTitle').value.trim()||!$('proposalContent').value.trim())return note('proposalNotice','Enter a title and proposal content.',true);try{await api('/api/proposals',{method:'POST',body:JSON.stringify({lead_id:l?.id||null,title:$('proposalTitle').value,content:$('proposalContent').value,state:'draft'})});await loadAll();note('proposalNotice','Proposal saved to your workspace.');}catch(e){note('proposalNotice',e.message,true);}});
$('followForm').addEventListener('submit',async e=>{e.preventDefault();try{const due=$('followDue').value?zonedDateTimeToIso($('followDue').value,state.preferences?.timezone||localTimezone()):null;await api('/api/followups',{method:'POST',body:JSON.stringify({lead_id:$('followLead').value,title:$('followTitle').value,due_at:due,notes:$('followNotes').value})});e.target.reset();await loadAll();note('followNotice','Follow-up task saved.');}catch(e){note('followNotice',e.message,true);}});
$('followList').addEventListener('click',async e=>{const b=e.target.closest('[data-follow-done]');if(!b)return;try{await api('/api/followups/'+encodeURIComponent(b.dataset.followDone),{method:'PATCH',body:JSON.stringify({state:'done'})});await loadAll();}catch(e){toast(e.message,true);}});
$('draftList').addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;try{if(b.dataset.copyDraft){const d=state.drafts.find(x=>x.id===b.dataset.copyDraft);if(d)await copyTextToClipboard('Subject: '+d.subject+'\n\n'+d.body,'emailNotice','Saved email copied to clipboard.');}else if(b.dataset.gmail){if(!confirm('Create this message as a draft in Gmail? It will not be sent.'))return;const d=await api('/api/drafts/'+encodeURIComponent(b.dataset.gmail)+'/gmail',{method:'POST'});note('emailNotice',d.message);toast(d.message);}else if(b.dataset.deleteDraft){await api('/api/drafts/'+encodeURIComponent(b.dataset.deleteDraft),{method:'DELETE'});await loadAll();}}catch(e){toast(e.message,true);}});
$('proposalList').addEventListener('click',()=>{});
$('gmailConnect').addEventListener('click',()=>{location.href='/api/integrations/gmail/start';});
$('gmailDisconnect').addEventListener('click',async()=>{try{await api('/api/integrations/gmail',{method:'DELETE'});await loadAll();note('gmailNotice','Gmail disconnected.');}catch(e){note('gmailNotice',e.message,true);}});
$('downloadExport').addEventListener('click',()=>{const pack={exported_at:new Date().toISOString(),leads:state.leads,drafts:state.drafts,followups:state.followups,proposals:state.proposals};const blob=new Blob([JSON.stringify(pack,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='mcas-workspace-export.json';a.click();URL.revokeObjectURL(a.href);note('exportNotice','Workspace export downloaded. Protect this file; it contains customer information.');});
function queryFlags(){const u=new URL(location.href);if(u.searchParams.get('gmail')==='connected')note('gmailNotice','Google Gmail connected successfully.');else if(u.searchParams.get('gmail')==='cancelled')note('gmailNotice','Gmail connection was cancelled.');if(u.searchParams.has('gmail')){u.searchParams.delete('gmail');history.replaceState({},'',u.pathname);}}

const advisorProfiles={
 professional:{type:'Professional services website',pages:['Home with a clear value proposition','Services / expertise pages','About and credentials','Case studies or testimonials (with permission)','Contact / consultation request'],features:['Clear enquiry form with spam protection','Service-specific calls to action','Trust signals: credentials, team and verified testimonials','Search-friendly service and location pages'],quality:['Credible, restrained visual design','Fast mobile-first layouts','Accessible typography and contrast','Clear service descriptions and next steps']},
 retail:{type:'E-commerce storefront',pages:['Home / featured collections','Product catalogue and product detail pages','Cart and secure checkout','Delivery, returns and FAQs','Contact and order support'],features:['Inventory and product management','Secure payment gateway selected for the target market','Delivery / collection rules','Order confirmation and abandoned-cart plan'],quality:['Consistent product photography','Transparent prices and delivery costs','Simple checkout with minimal steps','Strong mobile shopping experience']},
 restaurant:{type:'Restaurant website with online reservations or ordering',pages:['Home with menu highlights','Menu with prices and dietary notes','Reservations or ordering','Location, opening hours and directions','Gallery and contact'],features:['Tap-to-call and map directions','Reservation / ordering workflow','Menu that is easy to update','Social proof and current opening hours'],quality:['Mobile-first menu readability','Fast-loading compressed images','Prominent booking / order buttons','Accurate hours, address and contact details']},
 health:{type:'Healthcare practice website',pages:['Home and practice overview','Treatments / services','Practitioners and qualifications','Appointment request','Location, hours and patient FAQs'],features:['Appointment enquiry (avoid collecting unnecessary sensitive data)','Clear emergency / urgent-care guidance','Practitioner credentials and policies','Privacy notice and secure form handling'],quality:['Calm, accessible design','Plain-language service information','High trust and privacy standards','Very clear contact and appointment steps']},
 education:{type:'Education or training website',pages:['Home and learning outcomes','Courses / programmes','Instructors and accreditation','Admissions / registration','FAQs and contact'],features:['Course catalogue and schedules','Application / registration form','Learning resources or LMS integration if needed','Payment integration only if required'],quality:['Clear programme outcomes and prerequisites','Accessible content and navigation','Trustworthy credentials and policies','Responsive pages for mobile learners']},
 realestate:{type:'Real-estate listings and lead-generation website',pages:['Home with property search','Property listing results','Individual property details','Agent / company profile','Viewing request and contact'],features:['Search and filters','Property photo galleries and key facts','Viewing enquiry forms','CRM integration or lead notifications'],quality:['Accurate, current listing data','Fast image delivery','Strong filters and map usability','Prominent viewing calls to action']},
 creative:{type:'Portfolio and personal-brand website',pages:['Home / positioning statement','Selected work and case studies','Services and process','About / experience','Contact / project enquiry'],features:['Project gallery with detailed case studies','Strong calls to action','Testimonials with permission','Content management for adding new work'],quality:['Distinctive but consistent art direction','Visual hierarchy that showcases work','Fast optimized media','Easy-to-use mobile portfolio']},
 nonprofit:{type:'Non-profit / community information website',pages:['Mission and impact','Programmes / initiatives','Stories and updates','Volunteer / partner information','Donate / contact'],features:['Donation provider integration if needed','Volunteer and partner forms','Impact reporting','Accessible event and news publishing'],quality:['Transparent use-of-funds information','Accessible, inclusive content','Clear impact evidence','Simple donation and volunteer journeys']},
 local:{type:'Local service-business website',pages:['Home with service area','Services and indicative pricing','Work gallery / before-and-after (with permission)','Reviews / trust signals','Quote request and contact'],features:['Click-to-call and WhatsApp link where appropriate','Quote / booking form','Service-area pages','Google Business Profile link and review process'],quality:['Local search-friendly information','Clear service coverage and hours','Prominent phone / enquiry buttons','Mobile speed and readability']},
 startup:{type:'SaaS product marketing website',pages:['Home with product promise','Features and use cases','Pricing / plans','Security, FAQs and documentation','Demo / signup / contact'],features:['Product demo or waitlist flow','Analytics with consent-aware setup','Customer onboarding path','Status, support and documentation links'],quality:['Specific, credible value proposition','Product screenshots and proof','Transparent pricing and limitations','Fast, accessible conversion funnel']}
};
function renderWebsiteAdvice(){
 const industry=$('advisorIndustry').value,goal=$('advisorGoal').value,presence=$('advisorPresence').value,budget=$('advisorBudget').value,context=$('advisorContext').value.trim();
 const p=advisorProfiles[industry];
 const goalText={leads:'Lead-generation and enquiry conversion',sales:'Online sales / booking conversion',trust:'Credibility and clear service communication',operations:'Workflow automation and operational efficiency',community:'Information sharing and community engagement'}[goal];
 const presenceText={none:'Build a focused first website with only essential pages and a clear next step.',basic:'Prioritise a redesign audit, mobile usability, content clarity and conversion fixes before adding complex features.',social:'Create an owned website hub and connect social channels; do not assume social followers will convert without a clear offer.',existing:'Improve the current site based on analytics, user feedback and measurable friction rather than rebuilding automatically.',unknown:'Run a discovery review of the existing presence before recommending a rebuild.'}[presence];
 const budgetText={starter:'Start with a lean, maintainable build: essential pages, contact conversion and a simple content update process.',growth:'Plan a polished multi-page site with the highest-value integrations and a manageable content workflow.',advanced:'Consider custom workflows and integrations only after validating requirements, ownership, support and total cost.',unknown:'Confirm budget, content ownership, hosting and ongoing maintenance before fixing the scope.'}[budget];
 const goalAdd={leads:['Focused landing pages for priority services','Short enquiry form with clear response expectations'],sales:['Product / service catalogue and conversion path','Payment, booking or order workflow matched to the business'],trust:['Strong about, credentials and proof pages','Consistent brand system and clear service explanations'],operations:['Map the current process before automating it','Role-based workflows, notifications and integrations only where justified'],community:['Useful resource / update publishing','Accessible event, membership or volunteer pathways']}[goal];
 const improvements=[];
 if(presence==='none'||presence==='social')improvements.push('Establish a clear domain, business identity, core pages and one primary conversion action.');
 if(presence==='basic'||presence==='existing')improvements.push('Review mobile layout, load performance, navigation, content accuracy and broken links; prioritise issues by user impact.');
 improvements.push('Add descriptive page titles, headings, metadata, sitemap and locally relevant content where appropriate.');
 improvements.push('Compress images, use responsive image sizes, caching and a performance budget.');
 improvements.push('Check keyboard navigation, form labels, contrast and readable text sizes.');
 improvements.push('Add privacy notice, consent-aware analytics and secure form handling where applicable.');
 const ctx=context?'<p><b>Discovery notes to validate:</b> '+esc(context)+'</p>':'<p><b>Discovery gap:</b> Add verified observations from a client interview and website review before presenting this as a tailored proposal.</p>';
 const htmlOut='<div class="item"><span class="badge green">Suggested direction</span><h3>'+esc(p.type)+'</h3><p><b>Primary outcome:</b> '+esc(goalText)+'.</p><p>'+esc(presenceText)+'</p><p>'+esc(budgetText)+'</p>'+ctx+'</div>'+
 '<div class="item"><h3>Recommended site map</h3><ul>'+p.pages.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul></div>'+
 '<div class="item"><h3>Recommended features</h3><ul>'+p.features.concat(goalAdd).map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul></div>'+
 '<div class="item"><h3>Quality standards</h3><ul>'+p.quality.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul></div>'+
 '<div class="item"><h3>Improvement roadmap</h3><ol>'+improvements.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ol></div>'+
 '<div class="warning"><b>Scope and validation:</b> This recommendation is rules-based guidance, not a verified technical audit or market study. Confirm the business goals, users, content, budget, integrations, legal requirements and maintenance responsibilities with the client before quoting. Do not promise rankings, revenue or conversion results.</div>';
 $('advisorOutput').innerHTML=htmlOut;
 note('advisorNotice','Recommendation generated. Use it as a discovery and proposal starting point, then validate it with the business owner.');
}
$('advisorGenerate').addEventListener('click',renderWebsiteAdvice);

/* Prospect-linked Website Advisor. This is deterministic and uses only saved MCAS evidence. */
let advisorLatestAudit=null;
let advisorAuditLeadId=null;
function advisorProspect(){return selectedLead($('advisorLead')?.value||'');}
function inferAdvisorIndustry(lead){
 const source=((lead.name||'')+' '+(lead.evidence||'')+' '+(lead.market||'')).toLowerCase();
 if(/restaurant|cafe|hotel|hospitality|food|takeaway|bar\b/.test(source))return 'restaurant';
 if(/salon|barber|beauty|spa|nail/.test(source))return 'local';
 if(/shop|retail|supermarket|fashion|boutique|store|e-commerce/.test(source))return 'retail';
 if(/clinic|hospital|medical|health|dental|pharmacy/.test(source))return 'health';
 if(/school|college|university|training|education|academy/.test(source))return 'education';
 if(/real estate|property|estate agent|realtor|property management/.test(source))return 'realestate';
 if(/church|charity|non.?profit|ngo|foundation|community/.test(source))return 'nonprofit';
 if(/software|saas|startup|technology|tech company/.test(source))return 'startup';
 if(/photographer|designer|artist|creative|portfolio|studio/.test(source))return 'creative';
 if(/consult|law|account|finance|professional|agency/.test(source))return 'professional';
 return 'local';
}
function updateAdvisorProspect(){
 const lead=advisorProspect();
 if(!lead){
  $('advisorLeadSummary').textContent='Choose a saved prospect to load its research evidence, or continue with the manual business profile below.';
  $('advisorDiagnosis').innerHTML='<div class="empty">Select a saved prospect to inspect its recorded research findings.</div>';
  $('advisorLiveAuditBtn').disabled=true;
  return;
 }
 $('advisorIndustry').value=inferAdvisorIndustry(lead);
 const ev=(lead.evidence||'').toLowerCase();
 $('advisorPresence').value=lead.website?(/returned http [45]\d\d/i.test(lead.evidence||'')?'basic':'existing'):'unknown';
 $('advisorContext').value=lead.evidence||('Saved prospect: '+lead.name+'. Add verified discovery notes before finalising the scope.');
 $('advisorLeadSummary').innerHTML='<b>'+esc(lead.name)+'</b><br>'+esc(lead.market||'Location not recorded')+' · '+esc(lead.website||'No website URL saved')+'<br><span class="tiny">Prospect status: '+esc(lead.status||'Unverified')+(lead.score?' · Research priority: '+esc(lead.score)+'/100':'')+'</span>';
 $('advisorLiveAuditBtn').disabled=!lead.website;
 advisorLatestAudit=null;advisorAuditLeadId=null;
 renderAdvisorDiagnosis(lead,null);
}
function advisorFinding(title,detail,level){
 return '<div class="item"><div class="itemtop"><strong>'+esc(title)+'</strong><span class="badge '+(level==='high'?'red':level==='medium'?'amber':'')+'">'+esc(level==='high'?'Needs attention':level==='medium'?'Check':'Unverified')+'</span></div><p>'+esc(detail)+'</p></div>';
}
function advisorFindings(lead,audit){
 const text=String(lead?.evidence||'');
 const lower=text.toLowerCase();
 const out=[];
 if(!lead)return ['<div class="empty">Select a prospect first. The diagnosis will be based on its saved research evidence.</div>'];
 if(!lead.website){
  if(lower.includes('did not return an official website url')||lower.includes('no website url')||lower.includes('website url is not listed')){
   out.push(advisorFinding('No official website link returned', 'MCAS research did not receive an official website URL from the discovery provider. This does not prove the business has no website; verify with the owner and search independently before stating that it has none.','medium'));
  }else{
   out.push(advisorFinding('Website not recorded','No website address is saved on this prospect. MCAS cannot diagnose the website until a verified public URL is added.','unverified'));
  }
 }
 const combined=(text+' '+(audit?JSON.stringify(audit):'')).toLowerCase();
 const httpMatch=combined.match(/returned http\s+(\d{3})/i);
 const status=audit?.http_status??(httpMatch?Number(httpMatch[1]):null);
 if(status!==null&&status!==undefined&&Number(status)>=400){
  const code=Number(status);
  const level=code>=500?'high':'medium';
  out.push(advisorFinding('Website returned HTTP '+code,'The page returned this status during a limited automated check. It may be temporary, path-specific or caused by access controls; open the site manually and confirm before presenting it as a confirmed outage.',level));
 }else if(status!==null&&status!==undefined&&Number(status)>=200&&Number(status)<400){
  out.push(advisorFinding('Website responded to the check','The checked URL returned HTTP '+Number(status)+'. This only confirms a basic response; it does not establish that the site is fast, accessible, secure, persuasive or working correctly for customers.','unverified'));
 }
 const viewport=audit?audit.has_viewport_meta===false:lower.includes('mobile viewport metadata not detected');
 if(viewport)out.push(advisorFinding('Mobile viewport metadata not detected','The lightweight check did not find a viewport meta tag on the checked page. Verify the layout on real phones; the metadata result alone does not prove every page is non-responsive.','medium'));
 const description=audit?audit.has_meta_description===false:lower.includes('meta description not detected');
 if(description)out.push(advisorFinding('Meta description not detected','The checked page did not expose a meta description in the limited HTML scan. Add a unique, accurate description for important pages after reviewing the content.','medium'));
 const title=audit?(!audit.title):lower.includes('page title not detected');
 if(title)out.push(advisorFinding('Page title not detected','The checked page did not expose a title in the limited HTML scan. Add a descriptive page title that reflects the business and page purpose.','medium'));
 const h1=audit?audit.has_h1===false:false;
 if(h1)out.push(advisorFinding('Main heading not detected','The lightweight HTML scan did not find an H1 heading on the checked page. Review the page hierarchy and add one clear, descriptive primary heading where appropriate.','low'));
 const form=audit?audit.has_form===false:false;
 if(form)out.push(advisorFinding('No HTML form detected on the checked page','The first fetched page did not contain a standard HTML form. This may be intentional if the site uses phone, WhatsApp or a booking widget; verify that customers still have a clear enquiry path.','low'));
 if(lower.includes('restricted this automated check')||(audit&&[401,403,429].includes(Number(audit.http_status)))){
  out.push(advisorFinding('Automated check was restricted','The site restricted the automated request. MCAS cannot conclude that it is broken; inspect it manually in a browser.','unverified'));
 }
 if(!out.length){
  out.push(advisorFinding('No specific technical defect established','The saved research contains no clear technical failure or missing metadata finding. The full site still needs a manual review and a conversation with the business owner.','unverified'));
 }
 return out;
}
function renderAdvisorDiagnosis(lead,audit){
 const findings=advisorFindings(lead,audit);
 const source=lead?.source_url?'<p class="tiny">Research source: <a href="'+safeLink(lead.source_url)+'" target="_blank" rel="noopener noreferrer">Open source listing</a></p>':'';
 const site=lead?.website?'<p class="tiny">Website checked: <a href="'+safeLink(lead.website)+'" target="_blank" rel="noopener noreferrer">'+esc(lead.website)+'</a></p>':'';
 $('advisorDiagnosis').innerHTML=findings.join('')+site+source+'<div class="warning"><b>Evidence boundary:</b> These are saved research observations or a lightweight public-page check, not a full SEO, accessibility, security, performance or conversion audit. Recommendations below are proposed improvements, not diagnosed defects.</div>';
}
async function runAdvisorLiveAudit(){
 const lead=advisorProspect();
 if(!lead)return note('advisorNotice','Choose a saved prospect first.',true);
 if(!lead.website)return note('advisorNotice','This prospect has no saved website URL. Add and verify a public URL before running a check.',true);
 const btn=$('advisorLiveAuditBtn');btn.disabled=true;btn.textContent='Checking website…';
 try{
  const result=await api('/api/audit-website',{method:'POST',body:JSON.stringify({url:lead.website,lead_id:lead.id,max_pages:10})});
  advisorLatestAudit=result;advisorAuditLeadId=lead.id;
  lead.website_status=result.website_status||lead.website_status;
  lead.website_verified_at=result.website_status==='verified'?result.checked_at:null;
  renderAdvisorDiagnosis(lead,result);
  note('advisorNotice','Fresh bounded multi-page website audit complete. Prospect website status has been refreshed; findings are separated from recommendations.');
 }catch(e){note('advisorNotice','Website check could not be completed: '+e.message,true);}
 finally{btn.disabled=false;btn.textContent='Run fresh website check';}
}
function advisorPlanData(){
 const industry=$('advisorIndustry').value,goal=$('advisorGoal').value,budget=$('advisorBudget').value;
 const p=advisorProfiles[industry]||advisorProfiles.local;
 const goalLabels={leads:'Generate qualified enquiries and leads',sales:'Sell products, accept orders or bookings online',trust:'Build credibility and explain services clearly',operations:'Improve or automate a defined business workflow',community:'Share information and build a community'};
 const additions={
  leads:['Service-specific landing sections','Short enquiry form with consent and spam protection','Call and WhatsApp actions where appropriate'],
  sales:['Product or service catalogue','Transparent pricing, delivery and returns information','Checkout or booking flow with confirmation and support'],
  trust:['Credentials and team profiles supplied by the business','Case studies and testimonials only with permission','Clear policies, process and contact details'],
  operations:['Documented user roles and process map','Secure admin workflow and audit trail where needed','Integration only after access, data and ownership are agreed'],
  community:['News, resources or events publishing','Accessible volunteer, membership or contact pathways','Moderated forms and clear privacy rules']
 };
 const pages=p.pages.slice();
 const required=['Privacy notice and cookie/analytics choices where applicable','Terms, refund, delivery or booking policies appropriate to the business','Accessible 404 page and useful success/error states','Thank-you / form confirmation state','Contact details and social links verified by the owner'];
 const universal=['Responsive mobile-first layout for small phones, tablets and desktops','Consistent navigation, footer, typography, spacing and brand colours','Clear primary call-to-action on every important page','Optimised images, lazy loading where suitable and fast page delivery','Semantic headings, keyboard navigation, labelled forms and adequate colour contrast','Per-page titles, meta descriptions, clean URLs, sitemap and robots.txt','HTTPS-ready forms, validation, anti-spam controls and minimal data collection','Analytics only with appropriate consent and a privacy notice','Content management or a clear owner-editable content process','Cross-browser and real-device quality assurance'];
 return {industry:industry,goal:goal,budget:budget,profile:p,pages:pages,features:[...p.features,...(additions[goal]||[])],quality:p.quality,required:required,universal:universal,market:$('advisorContext').value.trim()};
}
function advisorPrice(data,lead){
 const industry=data.industry,goal=data.goal,budget=data.budget;
 let item={label:'Professional small-business website',low:35000,high:120000,scope:'Approximately 5–12 informative pages, mobile-first design, contact journey and foundational SEO.'};
 if(budget==='starter'&&(industry!=='retail'||goal!=='sales')&&goal!=='operations'){
  item={label:'Starter / template-led business website',low:15000,high:40000,scope:'A lean, mainly informational build with essential pages and one main enquiry action.'};
 }else if(industry==='retail'&&goal==='sales'){
  item={label:'E-commerce website with local payment integration',low:80000,high:250000,scope:'Catalogue, product pages, cart, checkout, order workflow and payment integration such as M-Pesa where required.'};
 }else if(industry==='realestate'){
  item={label:'Property listings and lead-generation website',low:120000,high:500000,scope:'Property catalogue, search/filtering, listing detail pages, enquiry and viewing-request flows. More advanced integrations and large listing inventories may cost more.'};
 }else if(goal==='operations'||(industry==='startup'&&budget==='advanced')){
  item={label:'Custom portal or web workflow',low:150000,high:500000,scope:'User roles, custom data workflows, dashboards and integrations; complex systems may exceed this range.'};
 }else if((industry==='restaurant'&&goal==='sales')||goal==='sales'){
  item={label:'Booking, ordering or commerce-enabled website',low:40000,high:150000,scope:'Service or product presentation plus booking/order requests; payments and operational integrations can increase scope.'};
 }else if(industry==='startup'){
  item={label:'SaaS / product marketing website',low:60000,high:180000,scope:'Product positioning, feature pages, pricing, FAQs, documentation entry points and demo/signup conversion.'};
 }else if(budget==='advanced'){
  item={label:'Custom-designed multi-page business website',low:80000,high:250000,scope:'Custom layouts, expanded content structure, advanced interactions and selected integrations.'};
 }
 return item;
}
async function prepareRegionalPrice(price){
 const p=state.preferences||{country_code:'KE',currency_code:'KES',pricing_multiplier:1};
 const multiplier=Number(p.pricing_multiplier||regionalPriceDefaults[p.country_code]||1);
 price.market_multiplier=multiplier;price.base_low_kes=price.low;price.base_high_kes=price.high;
 price.low*=multiplier;price.high*=multiplier;price.display_currency=p.currency_code||'KES';price.fx_updated_at=null;price.fx_source='MCAS planning estimate';
 const fmt=n=>new Intl.NumberFormat(p.language_code||'en',{style:'currency',currency:price.display_currency,maximumFractionDigits:0}).format(n);
 if(price.display_currency==='KES'){price.display_low=fmt(price.low);price.display_high=fmt(price.high);return price;}
 try{const fx=await api('/api/fx/convert?amount_kes=1&currency='+encodeURIComponent(price.display_currency));const rate=Number(fx.amount);if(!Number.isFinite(rate)||rate<=0)throw new Error('Invalid exchange rate');price.display_low=fmt(price.low*rate);price.display_high=fmt(price.high*rate);price.fx_updated_at=fx.updated_at;price.fx_source=fx.source;price.fx_rate=rate;}
 catch(error){price.fx_error=error.message;price.display_currency='KES';const kesFmt=n=>new Intl.NumberFormat(p.language_code||'en',{style:'currency',currency:'KES',maximumFractionDigits:0}).format(n);price.display_low=kesFmt(price.low);price.display_high=kesFmt(price.high);}
 return price;
}
function buildAdvisorPrompt(data,lead,price){
 const name=lead?.name||'BUSINESS NAME TO CONFIRM';
 const market=lead?.market||'Location to confirm';
 const website=lead?.website||'No verified website URL is recorded; do not assume one exists.';
 const evidence=lead?.evidence||$('advisorContext').value.trim()||'No prospect research evidence supplied. Ask for verified facts and use neutral placeholders.';
 const diagnosis=advisorFindings(lead,advisorAuditLeadId===lead?.id?advisorLatestAudit:null)
  .map(x=>x.replace(/<[^>]*>/g,' ').replace(/\s+/g,' ').trim()).join('\n- ');
 const pages=data.pages.map((x,i)=>(i+1)+'. '+x).join('\n');
 const features=data.features.map(x=>'- '+x).join('\n');
 const quality=data.universal.concat(data.quality).map(x=>'- '+x).join('\n');
 return [
 'AI WEBSITE BUILDER PROMPT — '+name,
 '',
 'ROLE AND OBJECTIVE',
 'Act as a senior UX designer, brand designer, conversion strategist and experienced web developer. Build a polished, complete, responsive business website for the real business described below. This is a WEBSITE project, not an unrelated mobile app. Use the strongest native website/CMS capabilities of the builder. Do not stop at a wireframe or generic landing-page mockup.',
 '',
 'BUSINESS PROFILE',
 'Business: '+name,
 'Location / market: '+market,
 'Industry: '+data.profile.type,
 'Current website: '+website,
 'Primary business goal: '+({leads:'Generate qualified enquiries and leads',sales:'Sell products, accept orders or bookings online',trust:'Build credibility and communicate services',operations:'Support a defined business workflow',community:'Share information and build a community'}[data.goal]||data.goal),
 'Research notes supplied by MCAS: '+evidence,
 '',
 'DIAGNOSED / RESEARCHED OBSERVATIONS — HANDLE CAREFULLY',
 '- '+diagnosis,
 'Use only these observations as evidence. Do not turn unverified or restricted checks into claims that the business has no website or that its website is broken. Treat proposed improvements as recommendations, not proven defects.',
 '',
 'RECOMMENDED SITE STRUCTURE',
 pages,
 '',
 'REQUIRED FUNCTIONAL FEATURES',
 features,
 '- '+data.required.join('\n- '),
 '',
 'DESIGN AND CONTENT DIRECTION',
 '- Create a distinctive, credible visual identity suited to this industry and target audience; avoid a generic template look.',
 '- Use a clear visual hierarchy, readable typography, deliberate spacing, consistent components and authentic imagery relevant to the business.',
 '- Use the business name and supplied facts accurately. For missing phone numbers, email, address, prices, opening hours, team members, testimonials, credentials or product details, insert clearly labelled editable placeholders and request confirmation. Never invent them.',
 '- Make the principal action obvious: '+({leads:'request a quote / make an enquiry',sales:'book, order or purchase',trust:'contact the business or request a consultation',operations:'start the agreed workflow or request a demonstration',community:'join, participate or get in touch'}[data.goal]||'contact the business')+'.',
 '',
 'TECHNICAL, SEO, ACCESSIBILITY AND QUALITY REQUIREMENTS',
 quality,
 '- Ensure all links, forms, menu items and buttons work. Include validation, helpful error messages, success states and a useful 404 page.',
 '- Make forms send data only to a configured endpoint chosen by the site owner; do not fabricate backend integrations or pretend submissions work without configuration.',
 '- Do not expose API keys, secret tokens or credentials in client-side code.',
 '',
 'DELIVERABLES',
 '- Complete page designs and working navigation for the sitemap above.',
 '- Reusable header, footer, buttons, cards, forms and responsive components.',
 '- Realistic page copy based only on supplied business information; use clearly marked placeholders for unknowns.',
 '- A concise handover note covering how the owner edits content, connects the domain, configures hosting, forms, analytics and any third-party integrations.',
 '',
 'SCOPE AND COMMERCIAL NOTE',
 'The MCAS estimate for the likely website category is '+price.label+': '+(price.display_low||price.low+' KES')+'–'+(price.display_high||price.high+' KES')+' in '+(price.display_currency||'KES')+'. The workspace pricing adjustment is '+Number(price.market_multiplier||1).toFixed(2)+'×. This is indicative planning guidance, not a formal quote or verified local market survey. Do not display it on the public website unless the owner requests it.',
 '',
 'Before building, state any essential missing information as questions or placeholders. Then create the full website. Prioritise clarity, trust, accessibility, mobile usability, maintainability and a useful customer journey.'
 ].join('\n');
}
async function generateAdvisorPlan(){
 const lead=advisorProspect();
 if($('advisorLead').value&&!lead)return note('advisorNotice','The selected prospect could not be found. Refresh the workspace and select it again.',true);
 const data=advisorPlanData();
 const price=await prepareRegionalPrice(advisorPrice(data,lead));
 renderAdvisorDiagnosis(lead,advisorAuditLeadId===lead?.id?advisorLatestAudit:null);
 const pageHtml=data.pages.map((x,i)=>'<li><b>'+esc(x)+'</b><br><span class="tiny">Define the page goal, primary content, proof points and a clear next action. Keep content specific to this business and verify all claims.</span></li>').join('');
 const featuresHtml=data.features.map(x=>'<li>'+esc(x)+'</li>').join('');
 const universalHtml=data.universal.concat(data.required).map(x=>'<li>'+esc(x)+'</li>').join('');
 $('advisorPlanOutput').innerHTML='<div class="item"><span class="badge green">Recommended website type</span><h3>'+esc(data.profile.type)+'</h3><p><b>Main goal:</b> '+esc(({leads:'Generate enquiries',sales:'Drive sales / bookings',trust:'Build credibility',operations:'Support business operations',community:'Engage a community'})[data.goal])+'</p></div>'+
 '<div class="item"><h3>Proposed sitemap and page purpose</h3><ol>'+pageHtml+'</ol></div>'+
 '<div class="item"><h3>Industry and goal-specific features</h3><ul>'+featuresHtml+'</ul></div>'+
 '<div class="item"><h3>Core website requirements</h3><ul>'+universalHtml+'</ul></div>'+
 '<div class="item"><h3>Design direction and quality standard</h3><ul>'+data.quality.map(x=>'<li>'+esc(x)+'</li>').join('')+'</ul></div>'+
 '<div class="warning"><b>Before build:</b> Confirm business facts, page content, owner access, integrations, data collected, domain, hosting, maintenance and acceptance criteria with the business. Do not publish placeholder claims or fake testimonials.</div>';
 const isKenya=(state.preferences?.country_code||'KE')==='KE';
 let marketNote=isKenya?'Published Kenyan 2026 price guides vary substantially by scope. MCAS uses broad Kenya-based planning bands, not a guaranteed market price.':'No independently verified local market-price survey is built in for this country. MCAS starts from its Kenya scope bands and applies your editable regional multiplier; validate these figures with local suppliers before quoting.';
 const fxNote=price.display_currency==='KES'?'Shown in KES base currency.':(price.fx_updated_at?'Exchange rates last updated '+price.fx_updated_at+'.':'Exchange-rate conversion was unavailable; shown in KES instead.');
 const recurringCostNote=isKenya?'Indicative Kenya operating costs only; not applicable as a local quote elsewhere.':'MCAS does not contain a verified local hosting or maintenance survey for this country.';
 $('advisorPricingOutput').innerHTML='<div class="item"><span class="badge green">Indicative website project value · '+esc(price.display_currency)+'</span><h3>'+esc(price.label)+'</h3><div class="metric">'+esc(price.display_low)+' – '+esc(price.display_high)+'</div><p>'+esc(price.scope)+'</p><p class="tiny">Workspace country: '+esc(countryDisplay(state.preferences?.country_code||'KE'))+' · Regional pricing adjustment: '+Number(price.market_multiplier||1).toFixed(2)+'× · '+esc(fxNote)+' Excludes tax and third-party charges.</p><p class="tiny"><a href="https://www.exchangerate-api.com/" target="_blank" rel="noopener noreferrer">Exchange rates by ExchangeRate-API</a></p><p class="tiny">'+esc(marketNote)+'</p>'+(price.fx_error?'<p class="tiny">Currency conversion note: '+esc(price.fx_error)+'</p>':'')+'</div>'+
 '<div class="item"><h3>Possible recurring costs (budget separately)</h3><p>'+esc(recurringCostNote)+'</p><p class="tiny">Check local domain, hosting, email, payment fees, content production, tax and support costs before quoting.</p></div>'+
  (isKenya
    ? '<div class="item"><h3>Pricing references (Kenya, 2026)</h3><p><a href="https://wfw.co.ke/blog/how-much-does-a-website-cost-in-kenya" target="_blank" rel="noopener noreferrer">Wallflower Agency — business, company and e-commerce price guide (13 September 2026)</a></p><p><a href="https://www.thabititechnologies.com/blog/website-cost-in-kenya" target="_blank" rel="noopener noreferrer">Thabiti Technologies — website types and custom system ranges (4 October 2026)</a></p><p><a href="https://digital4africa.com/website-cost-kenya/" target="_blank" rel="noopener noreferrer">Digital4Africa — website and running-cost guide (October 2026)</a></p><p><a href="https://edgecom.co.ke/website-cost-kenya" target="_blank" rel="noopener noreferrer">Edgecom — published starting prices and VAT notes (October 2026)</a></p></div>'
    : '<div class="item"><h3>Local pricing validation</h3><p>Confirm local rates with at least two or three providers in the selected market. These MCAS figures are not a verified survey of local suppliers.</p></div>')+
 '<div class="warning"><b>Estimate only:</b> Actual value depends on the final page count, design, copywriting, integrations, e-commerce/booking workflow, data migration, hosting, support and developer experience. Confirm scope before quoting. Check applicable local tax treatment and third-party charges.</div>';
 $('advisorPromptText').value=buildAdvisorPrompt(data,lead,price);
 $('advisorPromptPanel').classList.remove('hide');
 note('advisorNotice','Full plan, evidence-led diagnosis, USD estimate and AI-builder prompt generated. Use Copy AI-builder prompt if clipboard access is blocked.');
 copyTextToClipboard($('advisorPromptText').value,'advisorNotice','AI-builder prompt generated and copied to clipboard.').catch(()=>{});
}
$('advisorLead').addEventListener('change',()=>{renderAdvisorProspectPicker();updateAdvisorProspect();});
$('advisorLeadPickerButton').addEventListener('click',()=>{const menu=$('advisorLeadPickerMenu');if(menu.classList.contains('hide'))openAdvisorProspectPicker();else closeAdvisorProspectPicker();});
$('advisorLeadSearch').addEventListener('input',renderAdvisorProspectPicker);
$('advisorLeadOptions').addEventListener('click',e=>{
 const choice=e.target.closest('[data-advisor-prospect-id]');if(!choice)return;
 const id=choice.dataset.advisorProspectId;
 if(!state.leads.some(l=>String(l.id)===String(id)))return;
 $('advisorLead').value=id;
 closeAdvisorProspectPicker();
 renderAdvisorProspectPicker();
 updateAdvisorProspect();
 $('advisorLeadPickerButton').focus();
});
$('advisorLeadSearch').addEventListener('keydown',e=>{
 if(e.key==='Escape'){closeAdvisorProspectPicker();$('advisorLeadPickerButton').focus();}
});
$('advisorLeadPickerButton').addEventListener('keydown',e=>{
 if(e.key==='Escape')closeAdvisorProspectPicker();
 if(e.key==='ArrowDown'&&!$('advisorLeadPickerMenu').classList.contains('hide')){$('advisorLeadOptions').querySelector('button')?.focus();}
});
document.addEventListener('click',e=>{if(!$('advisorProspectPicker')?.contains(e.target))closeAdvisorProspectPicker();});
$('advisorLiveAuditBtn').addEventListener('click',runAdvisorLiveAudit);
$('advisorBuildPlan').addEventListener('click',generateAdvisorPlan);
$('advisorCopyPrompt').addEventListener('click',()=>copyTextToClipboard($('advisorPromptText').value,'advisorNotice','AI-builder prompt copied to clipboard.'));


queryFlags();boot();
})();