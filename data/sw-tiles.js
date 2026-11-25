var CACHE='pwnterrey-tiles-v1';
self.addEventListener('fetch',function(ev){
  var u=ev.request.url;
  if(u.indexOf('.tile.openstreetmap.org')<0)return;
  ev.respondWith(
    caches.open(CACHE).then(function(cache){
      return cache.match(ev.request).then(function(cached){
        if(cached)return cached;
        return fetch(ev.request).then(function(resp){
          if(resp&&resp.status===200)cache.put(ev.request,resp.clone());
          return resp;
        }).catch(function(){return new Response('',{status:503})});
      });
    })
  );
});
