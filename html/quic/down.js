onmessage = function (ev) {
	console.log("In down  Worker")
	fetch("https://monitor.uac.bj:4448/download").then(response=>response.blob()).then(data=>{
		console.log('Fnished')
		postMessage(null)
	}).catch(err=>console.log(err))
}

