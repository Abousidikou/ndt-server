onmessage = function (ev) {
  'use strict'
  console.log("Download_Test")
  let start = performance.now()
  fetch("https://monitor.uac.bj:4448/download").then(response=>response.blob()).then(data=>{
  let v = performance.now() - start
  //console.log(data)
  //console.log(data.size*8)
  //console.log(v+" ms")
  let bms = (data.size*8)/v
  //console.log(bms+" bit/ms")
  let bs = bms*1000
  //console.log(bs + " bits/s")
  let mbs = bs/1000000
  console.log(Math.ceil(mbs)+" Mbps")
  postMessage({
          'AppInfo': {
            'ElapsedTime': v * 1000,  // us
            'NumBytes': data.size,
          },
          'Origin': 'client',
          'Test': 'download',
        })
  console.log("Success")
  postMessage(null)
  }).catch(err=>console.log(err))
}
