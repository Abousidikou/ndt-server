/* jshint esversion: 6, asi: true, worker: true */
// WebWorker that runs the ndt7 upload test
onmessage = function (ev) {
  'use strict'
  //Math.ceil((performance.now() - start)/1000)
  console.log("Upload_Test...")


  const initialMessageSize = 1 << 24 /* (1<<13) */
  const databuf = new Uint8Array(initialMessageSize) 
  var bl = new Blob([databuf], {type: "application/octet-stream"});
  let start = performance.now()
  console.log("bl: "+bl)
  fetch("https://monitor.uac.bj:4448/upload",{method: 'post', body: bl}).then(response=>response.text()).then(data=> {
  let v = performance.now() - start
  //console.log(v+ " ms")
  let bms = (initialMessageSize*8)/v
  //console.log(bms+" bits/ms")
  let bs = bms*1000
  //console.log(bs+" bits/s")
  let mbs = bs/1000000
  console.log(Math.ceil(mbs)+" Mbps")
  console.log(data)
  postMessage({
          'AppInfo': {
            'ElapsedTime': v * 1000,  // us
            'NumBytes': initialMessageSize,
          },
          'Origin': 'client',
          'Test': 'download',
        })
  postMessage(null)
  }).catch(err=>console.log(err));

}