onmessage = async function (ev) {
  console.log("Download_Test")
    let res,data,dataLengh=0,duration,previous,realTime=0,mbs=0,start = performance.now();
    while(true){
        previous = performance.now()
        res = await fetch("https://monitor.uac.bj:4448/download");
        duration = performance.now() - previous
        realTime += duration
        console.log("Realtime: "+realTime)
        duration = performance.now() - start
        data = await res.blob()
        let a = performance.now() - (duration+start)
        console.log('a:'+a)
        dataLengh += data.size
        console.log('duration: '+duration)
        console.log('datalen: '+dataLengh)
        if(duration >  13000 ){
            break;
        }
    }
    let resp = await fetch("https://monitor.uac.bj:4448/getDownSpeed?id="+duration);
    let sped = await  resp.text()
    let bs = parseInt(sped) // bs
    console.log(Math.ceil(bs)+" Mbps")
      await postMessage({
      'AppInfo': {
        'Speed': bs,  // Mbps
      },
      'Origin': 'client',
      'Test': 'download',
    })
    await postMessage(null)
}
