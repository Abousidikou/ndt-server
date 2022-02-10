
onmessage = function(ev){
    postMessage("In up new Worker()")
    var duration;
    var initialMessageSize = Math.pow(2, 24)
    var dat = genData(initialMessageSize)
    let start = performance.now()
    test(dat,start) 
}


async function test(dat,start){ 
        let v;
        while (true){    
        let response = await fetch("https://monitor.uac.bj:4448/upload",{method: 'post', body: dat});
        v = performance.now() - start
        console.log('duration: '+v)
        let data = await response.text()
        console.log(data)
        if (v > 13000){
          console.log(Math.ceil(v))
          break
        }
      }
      console.log("After while") 
      let res = await fetch("https://monitor.uac.bj:4448/getUpSpeed?id="+v);
      let bytes = await  res.text()
      let bms = (parseInt(bytes)*8)/parseInt(v) // bms
      let bs = bms * 1000
      let mbs = bs/1000000
      console.log(Math.ceil(mbs)+" Mbps")
      postMessage({
        'AppInfo': {
          'Speed': mbs,  // Mbps
        },
        'Origin': 'client',
        'Test': 'download',
      })
      postMessage(null)
  }
  
function genData(size){
  let myArray = new ArrayBuffer(size);
  let longInt8View = new Uint8Array(myArray);
  return longInt8View
}

