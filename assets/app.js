(()=>{'use strict';
const $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state={csrf:'',user:null,leads:[],drafts:[],followups:[],proposals:[],metrics:{},gmail:null,config:{search:false,ai:false},authMode:'login'};
function toast(msg,error=false){$('toast').textContent=msg;$('toast').className='notice'+(error?' error':'');}
function note(id,msg,error=false){$(id).textContent=msg;$(id).className='notice'+(error?' error':'');}
function cookie(name){const item=document.cookie.split('; ').find(x=>x.startsWith(name+'='));return item?decodeURIComponent(item.split('=').slice(1).join('=')):'';}
async function refreshCsrf(){const r=await fetch('/api/auth/csrf',{credentials:'same-origin'});if(!r.ok)throw new Error('Unable to initialise security token');const j=await r.json();state.csrf=j.csrf_token||cookie('mcas_csrf');}
async function api(path,opts={}){const method=(opts.method||'GET').toUpperCase();const headers={'Accept':'application/json',...(opts.headers||{})};if(opts.body!==undefined)headers['Content-Type']='application/json';if(['POST','PATCH','DELETE','PUT'].includes(method)){state.csrf=cookie('mcas_csrf')||state.csrf;headers['X-CSRF-Token']=state.csrf;}const r=await fetch(path,{...opts,method,headers,credentials:'same-origin'});const type=r.headers.get('content-type')||'';const data=type.includes('application/json')?await r.json():await r.text();if(!r.ok)throw new Error(data.detail||data.message||data||('Request failed ('+r.status+')'));return data;}
function showAuth(){ $('app').classList.add('hide');$('auth').classList.remove('hide');}
function showApp(){ $('auth').classList.add('hide');$('app').classList.remove('hide');$('signedEmail').textContent=state.user.email||'';}
function page(name){document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active',p.id===name));document.querySelectorAll('[data-page]').forEach(b=>b.classList.toggle('active',b.dataset.page===name));if(name==='prospects')renderLeads();if(name==='studio')renderDrafts();if(name==='followups')renderFollowups();if(name==='proposals')renderProposals();}
document.querySelectorAll('[data-page]').forEach(b=>b.addEventListener('click',()=>page(b.dataset.page)));
document.querySelectorAll('[data-go]').forEach(b=>b.addEventListener('click',()=>page(b.dataset.go)));
function setAuthMode(mode){state.authMode=mode;$('loginTab').classList.toggle('active',mode==='login');$('registerTab').classList.toggle('active',mode==='register');$('authSubmit').textContent=mode==='login'?'Sign in securely':'Create secure account';$('authPassword').autocomplete=mode==='login'?'current-password':'new-password';$('authPassword').minLength=mode==='login'?1:12;note('authNotice','');}
$('loginTab').addEventListener('click',()=>setAuthMode('login'));$('registerTab').addEventListener('click',()=>setAuthMode('register'));
$('authForm').addEventListener('submit',async e=>{e.preventDefault();const btn=$('authSubmit');btn.disabled=true;try{await refreshCsrf();const endpoint=state.authMode==='login'?'/api/auth/login':'/api/auth/register';const data=await api(endpoint,{method:'POST',body:JSON.stringify({email:$('authEmail').value,password:$('authPassword').value})});state.user=data;await refreshCsrf();showApp();await loadAll();}catch(err){note('authNotice',err.message,true);}finally{btn.disabled=false;}});
$('logoutBtn').addEventListener('click',async()=>{try{await api('/api/auth/logout',{method:'POST'});state.user=null;showAuth();}catch(e){toast(e.message,true);}});
async function boot(){try{await refreshCsrf();state.user=await api('/api/auth/me');showApp();await loadAll();}catch(e){showAuth();}}
async function loadAll(){try{const values=await Promise.all([api('/api/leads'),api('/api/drafts'),api('/api/followups'),api('/api/proposals'),api('/api/metrics'),api('/api/integrations/gmail/status'),api('/api/billing/status'),api('/api/integrations/status')]);[state.leads,state.drafts,state.followups,state.proposals,state.metrics,state.gmail,state.billing,state.config]=values;renderAll();$('searchBadge').textContent=state.config.web_search_configured?'Connected':'Needs API key';$('searchBadge').className='badge '+(state.config.web_search_configured?'green':'amber');$('aiBadge').textContent=state.config.ai_configured?'Connected':'Optional';$('aiBadge').className='badge '+(state.config.ai_configured?'green':'amber');$('researchConfig').textContent=state.config.web_search_configured?'Configured':'Set SERPER_API_KEY in .env and restart MCAS';$('aiConfig').textContent=state.config.ai_configured?'Configured':'Set AI_API_KEY in .env and restart MCAS';$('gmailBadge').textContent=state.gmail.connected?'Connected':state.gmail.configured?'Ready to connect':'Not configured';$('gmailDetails').textContent=state.gmail.capability||'Gmail drafts only.';$('gmailConnect').disabled=!state.gmail.configured||state.gmail.connected;$('gmailDisconnect').disabled=!state.gmail.connected;$('billingStatus').textContent=state.billing.message;}catch(e){toast(e.message,true);}}
function renderAll(){renderMetrics();renderLeads();renderDrafts();renderFollowups();renderProposals();renderSelects();}
function renderMetrics(){const m=state.metrics;$('mLeads').textContent=m.leads||0;$('mVerified').textContent=m.verified||0;$('mDrafts').textContent=m.pending_approval||0;$('mFollow').textContent=m.open_followups||0;$('pUnverified').textContent=state.leads.filter(l=>l.status==='Unverified').length;$('pPending').textContent=m.pending_approval||0;$('pDnc').textContent=m.do_not_contact||0;
$('recentLeads').innerHTML=state.leads.slice(0,5).map(l=>'<div class="row"><span><b>'+esc(l.name)+'</b><br><span class="tiny">'+esc(l.market||'')+'</span></span><span class="badge">'+esc(l.status)+'</span></div>').join('')||'<div class="empty">No prospects yet. Add your first lead.</div>';}
function renderSelects(){const options=state.leads.map(l=>'<option value="'+esc(l.id)+'">'+esc(l.name)+'</option>').join('');['emailLead','replyLead','proposalLead','followLead','advisorLead'].forEach(id=>{const el=$(id);if(!el)return;const old=el.value;el.innerHTML=options||'<option value="">Add a prospect first</option>';if(old&&state.leads.some(l=>l.id===old))el.value=old;});if($('advisorLead')&&$('advisorLead').value)updateAdvisorProspect();}
function renderLeads(){const q=($('leadFilter')?.value||'').toLowerCase(),st=$('leadFilterStatus')?.value||'';const items=state.leads.filter(l=>(!st||l.status===st)&&[l.name,l.market,l.evidence,l.contact_email].join(' ').toLowerCase().includes(q));$('leadList').innerHTML=items.map(l=>'<div class="item"><div class="itemtop"><strong>'+esc(l.name)+'</strong><span class="badge '+(l.do_not_contact?'red':l.status==='Verified'?'green':'')+'">'+esc(l.do_not_contact?'DO NOT CONTACT':l.status)+'</span></div><p>'+esc(l.market||'')+' · '+esc(l.website||'No website recorded')+'</p><p>'+esc(l.evidence||'No evidence recorded.')+'</p><p>'+esc(l.contact_email||'No contact email')+(l.source_url?' · <a href="'+safeLink(l.source_url)+'" target="_blank" rel="noopener noreferrer">Source</a>':'')+'</p><div class="itemactions"><button data-verify="'+esc(l.id)+'">Mark verified</button>'+(l.status!=='Won'?'<button data-win="'+esc(l.id)+'">Client accepted</button>':'<span class="badge green">Client accepted</span>')+(l.status==='Won'?'<button class="primary" data-builder-prompt="'+esc(l.id)+'">Generate AI-builder prompt</button>':'')+'<button data-dnc="'+esc(l.id)+'">'+(l.do_not_contact?'Remove DNC':'Do not contact')+'</button><button class="danger" data-delete-lead="'+esc(l.id)+'">Delete</button></div></div>').join('')||'<div class="empty">No prospects match this filter.</div>';renderSelects();}
function safeLink(raw){try{const u=new URL(raw,location.origin);return ['http:','https:'].includes(u.protocol)?esc(u.href):'#';}catch{return '#';}}
function renderDrafts(){$('draftList').innerHTML=state.drafts.map(d=>{const gmailAction=d.gmail_draft_id?'<span class="badge green">IN GMAIL DRAFTS</span>':(state.gmail?.connected&&d.to_email?'<button class="primary" data-gmail="'+esc(d.id)+'">Create Gmail draft</button>':'');return '<div class="item"><div class="itemtop"><strong>'+esc(d.subject)+'</strong><span class="badge amber">PENDING APPROVAL</span></div><p>'+esc(d.kind)+' · '+esc(d.to_email||'No recipient')+' · '+esc(d.created_at||'')+'</p><p>'+esc(d.body.slice(0,260))+(d.body.length>260?'…':'')+'</p><div class="itemactions">'+gmailAction+'<button class="danger" data-delete-draft="'+esc(d.id)+'">Delete</button></div></div>';}).join('')||'<div class="empty">No drafts saved yet.</div>';}
function renderFollowups(){$('followList').innerHTML=state.followups.map(f=>'<div class="item"><div class="itemtop"><strong>'+esc(f.title)+'</strong><span class="badge">'+esc(f.state)+'</span></div><p>'+esc(f.lead_name)+' · '+esc(f.due_at||'No due date')+'</p><p>'+esc(f.notes)+'</p>'+(f.state==='open'?'<div class="itemactions"><button data-follow-done="'+esc(f.id)+'">Mark complete</button></div>':'')+'</div>').join('')||'<div class="empty">No follow-up tasks yet.</div>';}
function renderProposals(){$('proposalList').innerHTML=state.proposals.map(p=>'<div class="item"><div class="itemtop"><strong>'+esc(p.title)+'</strong><span class="badge">'+esc(p.state)+'</span></div><p>'+esc(p.content.slice(0,300))+'…</p></div>').join('')||'<div class="empty">No proposals saved yet.</div>';}
$('leadFilter').addEventListener('input',renderLeads);$('leadFilterStatus').addEventListener('change',renderLeads);
$('leadForm').addEventListener('submit',async e=>{e.preventDefault();const data={name:$('leadName').value.trim(),website:$('leadWebsite').value.trim()||null,market:$('leadMarket').value.trim(),contact_email:$('leadEmail').value.trim()||null,contact_phone:$('leadPhone').value.trim()||null,source_url:$('leadSource').value.trim()||null,evidence:$('leadEvidence').value.trim(),status:$('leadStatus').value,do_not_contact:$('leadDnc').checked};try{await api('/api/leads',{method:'POST',body:JSON.stringify(data)});e.target.reset();$('leadMarket').value='Kenya';await loadAll();note('leadNotice','Prospect saved to your private workspace.');}catch(err){note('leadNotice',err.message,true);}});
$('leadList').addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;if(b.dataset.builderPrompt){try{note('builderPromptNotice','Generating website-builder prompt…');const d=await api('/api/leads/'+encodeURIComponent(b.dataset.builderPrompt)+'/builder-prompt',{method:'POST'});$('builderPromptText').value=d.prompt;$('builderPromptPanel').classList.remove('hide');note('builderPromptNotice',d.note);$('builderPromptPanel').scrollIntoView({behavior:'smooth',block:'nearest'});}catch(err){note('builderPromptNotice',err.message,true);}return;}const id=b.dataset.verify||b.dataset.win||b.dataset.dnc||b.dataset.deleteLead;if(!id)return;const l=state.leads.find(x=>x.id===id);if(!l)return;try{if(b.dataset.deleteLead){if(!confirm('Delete this prospect and related follow-up tasks?'))return;await api('/api/leads/'+encodeURIComponent(id),{method:'DELETE'});}else{const payload={name:l.name,website:l.website,market:l.market,evidence:l.evidence,status:b.dataset.win?'Won':b.dataset.verify?'Verified':l.status,contact_email:l.contact_email,contact_phone:l.contact_phone,source_url:l.source_url,do_not_contact:b.dataset.dnc?!l.do_not_contact:!!l.do_not_contact};await api('/api/leads/'+encodeURIComponent(id),{method:'PATCH',body:JSON.stringify(payload)});}await loadAll();}catch(err){toast(err.message,true);}});

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
   const contact='<p><b>Public contact:</b> '+contactEmail+' · '+contactPhone+'</p>';
   const pages=(x.pages||[]).map(v=>'<li>'+esc(v)+'</li>').join('');
   const delivery=x.duplicate?'Already saved in your CRM; no duplicate proposal or email draft was created.':(x.gmail_draft_created?'Proposal, MCAS draft and Gmail draft created; nothing was sent.':(x.contact_email?'Proposal and MCAS draft saved. Gmail draft was not created: '+esc(x.gmail_draft_error||'check the Gmail connection in Integrations.'):'Proposal and MCAS draft saved. No public email was listed, so add a recipient after verification.'));
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
$('auditBtn').addEventListener('click',async()=>{const url=$('auditUrl').value.trim();if(!url)return note('auditResult','Enter a public website URL.',true);$('auditBtn').disabled=true;note('auditResult','Checking website…');try{const d=await api('/api/audit-website',{method:'POST',body:JSON.stringify({url})});note('auditResult','HTTP '+d.http_status+' · Title: '+(d.title||'Not detected')+' · Mobile viewport tag: '+(d.has_viewport_meta===null?'Not checked':d.has_viewport_meta?'Found':'Not found')+' · '+d.note);}catch(e){note('auditResult',e.message,true);}finally{$('auditBtn').disabled=false;}});
function selectedLead(id){return state.leads.find(l=>l.id===id);}
function emailText(l){const name=l.name,evidence=(l.evidence||'').trim(),checked=evidence&&!/not checked|unknown|not verified|not yet verified/i.test(evidence),service=$('service').value.trim()||'professional, mobile-friendly websites';const evidenceLine=checked?'I noted this from the information available: '+evidence+' I have not treated this as a full audit.':'I came across your public business listing while researching '+(l.market||'your area')+'. I have not confirmed a specific website problem, so I do not want to make assumptions.';return 'Hello '+name+' team,\n\n'+evidenceLine+'\n\nI help businesses make it easier for customers to understand their services and get in touch through '+service+'. A practical starting point could be clear service information, a mobile-friendly layout and a simple enquiry path, shaped around what your team actually needs.\n\nWould a brief 10–15 minute conversation next week be useful? I can share a few relevant ideas first, with no obligation.\n\nBest regards,\n'+$('signature').value.trim()+'\n\nIf you would prefer not to receive another message from me, just reply and I will not contact you again.';}
$('genEmail').addEventListener('click',()=>{const l=selectedLead($('emailLead').value);if(!l)return note('emailNotice','Add a prospect first.',true);if(l.do_not_contact)return note('emailNotice','This prospect is marked do-not-contact. Outreach is blocked.',true);$('emailTo').value=l.contact_email||'';$('emailSubject').value='A website idea for '+l.name;$('emailBody').value=emailText(l);note('emailNotice','Draft generated from your recorded evidence. Verify before use.');});
async function aiDraft(task){const l=selectedLead(task==='reply'?$('replyLead').value:task==='proposal'?$('proposalLead').value:$('emailLead').value);if(!l)return note(task==='reply'?'replyNotice':task==='proposal'?'proposalNotice':'emailNotice','Select a prospect first.',true);if(l.do_not_contact&&task!=='reply')return note(task==='proposal'?'proposalNotice':'emailNotice','Prospect is marked do-not-contact; outreach draft blocked.',true);try{const incoming=task==='reply'?$('incoming').value.trim():'';const service=task==='reply'?$('replyService').value:$('service').value;const d=await api('/api/assistant/draft',{method:'POST',body:JSON.stringify({lead_id:l.id,task,prospect_name:l.name,market:l.market||'',service:service||'website services',evidence:l.evidence||'',incoming})});if(task==='email'){$('emailBody').value=d.draft;$('emailSubject').value='A website idea for '+l.name;note('emailNotice',d.warning);}if(task==='reply'){$('replyBody').value=d.draft;note('replyNotice','AI reply generated. Review and edit it, then choose Save edited reply as new draft. Nothing was saved or sent automatically.');}if(task==='proposal'){$('proposalContent').value=d.draft;note('proposalNotice',d.warning);}}catch(e){note(task==='reply'?'replyNotice':task==='proposal'?'proposalNotice':'emailNotice',e.message,true);}}
$('aiEmail').addEventListener('click',()=>aiDraft('email'));$('aiProposal').addEventListener('click',()=>aiDraft('proposal'));
async function saveDraft(kind,subject,body,to,leadId,noteId){try{await api('/api/drafts',{method:'POST',body:JSON.stringify({kind,subject,body,to_email:to||null,lead_id:leadId||null})});await loadAll();note(noteId,'Saved as pending approval. No email was sent.');}catch(e){note(noteId,e.message,true);}}
$('saveEmail').addEventListener('click',()=>{const id=$('emailLead').value;const l=selectedLead(id);if(l?.do_not_contact)return note('emailNotice','Do-not-contact is active; cannot save an outreach email.',true);if(!$('emailBody').value.trim())return note('emailNotice','Write a message first.',true);saveDraft('Cold email',$('emailSubject').value||'Website enquiry',$('emailBody').value,$('emailTo').value,id,'emailNotice');});
$('genReply').addEventListener('click',()=>aiDraft('reply'));
$('saveReply').addEventListener('click',()=>{if(!$('replyBody').value.trim())return note('replyNotice','Generate a reply first.',true);saveDraft('Client reply','Reply draft',$('replyBody').value,$('replyTo').value,$('replyLead').value,'replyNotice');});
$('genProposal').addEventListener('click',()=>{const l=selectedLead($('proposalLead').value);if(!l)return note('proposalNotice','Add a prospect first.',true);const title=$('proposalTitle').value||'Website project proposal for '+l.name;$('proposalTitle').value=title;$('proposalContent').value='PROJECT PROPOSAL\n'+title+'\n\nPrepared for: '+l.name+'\nMarket: '+(l.market||'Not specified')+'\n\n1. CURRENT CONTEXT\n'+(l.evidence||'The client requirements and current website condition must be confirmed before scope is finalised.')+'\n\n2. PROPOSED APPROACH\n• Discovery and confirmation of business goals\n• Information architecture and page structure\n• Responsive design and implementation\n• Contact / enquiry flow and essential integrations\n• Quality assurance, handover and launch support\n\n3. DELIVERABLES\nList the agreed pages, features, integrations, content responsibilities and handover items here.\n\n4. TIMELINE\n'+($('proposalTimeline').value||'To be agreed after scope confirmation')+'\n\n5. INVESTMENT\n'+($('proposalBudget').value||'Quotation to be confirmed after scope')+'\n\n6. ASSUMPTIONS AND EXCLUSIONS\nConfirm hosting, domain, third-party subscriptions, copywriting, maintenance and change requests in writing.\n\n7. NEXT STEPS\nApprove the final scope and written quotation before work begins.\n\nPrepared by: '+$('signature').value;note('proposalNotice','Editable proposal structure generated. Confirm scope and pricing before sharing.');});
$('saveProposal').addEventListener('click',async()=>{const l=selectedLead($('proposalLead').value);if(!$('proposalTitle').value.trim()||!$('proposalContent').value.trim())return note('proposalNotice','Enter a title and proposal content.',true);try{await api('/api/proposals',{method:'POST',body:JSON.stringify({lead_id:l?.id||null,title:$('proposalTitle').value,content:$('proposalContent').value,state:'draft'})});await loadAll();note('proposalNotice','Proposal saved to your workspace.');}catch(e){note('proposalNotice',e.message,true);}});
$('followForm').addEventListener('submit',async e=>{e.preventDefault();try{const due=$('followDue').value?new Date($('followDue').value).toISOString():null;await api('/api/followups',{method:'POST',body:JSON.stringify({lead_id:$('followLead').value,title:$('followTitle').value,due_at:due,notes:$('followNotes').value})});e.target.reset();await loadAll();note('followNotice','Follow-up task saved.');}catch(e){note('followNotice',e.message,true);}});
$('followList').addEventListener('click',async e=>{const b=e.target.closest('[data-follow-done]');if(!b)return;try{await api('/api/followups/'+encodeURIComponent(b.dataset.followDone),{method:'PATCH',body:JSON.stringify({state:'done'})});await loadAll();}catch(e){toast(e.message,true);}});
$('draftList').addEventListener('click',async e=>{const b=e.target.closest('button');if(!b)return;try{if(b.dataset.gmail){if(!confirm('Create this message as a draft in Gmail? It will not be sent.'))return;const d=await api('/api/drafts/'+encodeURIComponent(b.dataset.gmail)+'/gmail',{method:'POST'});note('emailNotice',d.message);toast(d.message);}else if(b.dataset.deleteDraft){await api('/api/drafts/'+encodeURIComponent(b.dataset.deleteDraft),{method:'DELETE'});await loadAll();}}catch(e){toast(e.message,true);}});
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
  const result=await api('/api/audit-website',{method:'POST',body:JSON.stringify({url:lead.website})});
  advisorLatestAudit=result;advisorAuditLeadId=lead.id;
  renderAdvisorDiagnosis(lead,result);
  note('advisorNotice','Fresh lightweight website check complete. Findings are shown separately from recommendations.');
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
function moneyKES(n){return 'KES '+Number(n).toLocaleString('en-KE');}
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
 'The MCAS estimate for the likely website category is '+price.label+': '+moneyKES(price.low)+'–'+moneyKES(price.high)+' as an indicative Kenya-market build range. This is not a budget instruction or a quote for the AI builder. Do not display this estimate on the public website unless the business owner specifically requests it.',
 '',
 'Before building, state any essential missing information as questions or placeholders. Then create the full website. Prioritise clarity, trust, accessibility, mobile usability, maintainability and a useful customer journey.'
 ].join('\n');
}
function generateAdvisorPlan(){
 const lead=advisorProspect();
 if($('advisorLead').value&&!lead)return note('advisorNotice','The selected prospect could not be found. Refresh the workspace and select it again.',true);
 const data=advisorPlanData();
 const price=advisorPrice(data,lead);
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
 let marketNote='Published Kenyan 2026 price guides vary substantially by scope: simple business sites commonly appear around KES 15,000–40,000; fuller company sites around KES 35,000–120,000; e-commerce commonly around KES 50,000–250,000; and custom portals around KES 120,000–500,000+. MCAS uses these as broad planning bands, not a guaranteed market price.';
 $('advisorPricingOutput').innerHTML='<div class="item"><span class="badge green">Indicative Kenya-market project value</span><h3>'+esc(price.label)+'</h3><div class="metric">'+moneyKES(price.low)+' – '+moneyKES(price.high)+'</div><p>'+esc(price.scope)+'</p><p class="tiny">'+esc(marketNote)+'</p></div>'+
 '<div class="item"><h3>Possible recurring costs (budget separately)</h3><p>Domain and hosting: approximately KES 3,500–15,000 per year. Optional maintenance: approximately KES 5,000–25,000 per month, depending on provider and scope.</p><p class="tiny">Indicative published guide figures; renewals, traffic, email, premium plugins, payment fees, content production and taxes may be additional.</p></div>'+
 '<div class="item"><h3>Pricing references (Kenya, 2026)</h3><p><a href="https://wfw.co.ke/blog/how-much-does-a-website-cost-in-kenya" target="_blank" rel="noopener noreferrer">Wallflower Agency — business, company and e-commerce price guide (13 September 2026)</a></p><p><a href="https://www.thabititechnologies.com/blog/website-cost-in-kenya" target="_blank" rel="noopener noreferrer">Thabiti Technologies — website types and custom system ranges (4 October 2026)</a></p><p><a href="https://digital4africa.com/website-cost-kenya/" target="_blank" rel="noopener noreferrer">Digital4Africa — website and running-cost guide (October 2026)</a></p><p><a href="https://edgecom.co.ke/website-cost-kenya" target="_blank" rel="noopener noreferrer">Edgecom — published starting prices and VAT notes (October 2026)</a></p></div>'+
 '<div class="warning"><b>Estimate only:</b> Actual value depends on the final page count, design, copywriting, integrations, e-commerce/booking workflow, data migration, hosting, support and developer experience. Confirm scope before quoting. Some published prices exclude VAT; check tax treatment and third-party charges separately.</div>';
 $('advisorPromptText').value=buildAdvisorPrompt(data,lead,price);
 $('advisorPromptPanel').classList.remove('hide');
 note('advisorNotice','Full plan, evidence-led diagnosis, Kenya pricing estimate and AI-builder prompt generated. Review the evidence and scope before using the prompt.');
}
$('advisorLead').addEventListener('change',updateAdvisorProspect);
$('advisorLiveAuditBtn').addEventListener('click',runAdvisorLiveAudit);
$('advisorBuildPlan').addEventListener('click',generateAdvisorPlan);
$('advisorCopyPrompt').addEventListener('click',async()=>{
 const text=$('advisorPromptText').value;
 if(!text.trim())return note('advisorNotice','Generate the full website plan first.',true);
 try{await navigator.clipboard.writeText(text);note('advisorNotice','AI-builder prompt copied. Paste it into your website builder.');}
 catch(e){$('advisorPromptText').focus();$('advisorPromptText').select();note('advisorNotice','Select the prompt and copy it manually with Ctrl+C.');}
});


queryFlags();boot();
})();