onmessage = async function (ev) {
  console.log("Download_Test")
    let res,data,dataLengh=0,duration,mbs=0,start = performance.now();
    while(true){
        res = await fetch("https://monitor.uac.bj:4448/download");
        duration = performance.now() - start
        data = await res.blob()
        dataLengh += data.size
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
