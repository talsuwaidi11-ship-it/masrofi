// مصروفي offline support: the page is fetched fresh when online and served from cache when offline.
// Account data never goes through here; it lives in the page's own storage and syncs with the server.
var C='masrofi-v2';
self.addEventListener('install',function(e){
  self.skipWaiting();
  e.waitUntil(caches.open(C).then(function(c){return c.addAll(['./','manifest.webmanifest','icons/icon-192.png'])}));
});
self.addEventListener('activate',function(e){
  e.waitUntil(caches.keys().then(function(ks){return Promise.all(ks.filter(function(k){return k!==C}).map(function(k){return caches.delete(k)}))}).then(function(){return self.clients.claim()}));
});
self.addEventListener('fetch',function(e){
  var r=e.request; if(r.method!=='GET')return;
  var u=new URL(r.url);
  if(r.mode==='navigate'&&u.origin===location.origin){
    e.respondWith(fetch(r).then(function(res){if(res.ok){var cp=res.clone(); caches.open(C).then(function(c){c.put('./',cp)})} return res})
      .catch(function(){return caches.match('./')}));
    return;
  }
  var lib=/^(fonts\.googleapis\.com|fonts\.gstatic\.com|cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com)$/.test(u.host);
  var own=u.origin===location.origin&&/\.(png|webmanifest)$/.test(u.pathname);
  if(!lib&&!own)return;
  e.respondWith(caches.match(r).then(function(hit){
    return hit||fetch(r).then(function(res){if(res.ok||res.type==='opaque'){var cp=res.clone(); caches.open(C).then(function(c){c.put(r,cp)})} return res});
  }));
});
