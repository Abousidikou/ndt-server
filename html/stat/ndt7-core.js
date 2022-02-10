/* jshint esversion: 6, asi: true */
// ndt7core is a simple ndt7 client API.
const ndt7core = (function() {
  return {
    // run runs the specified test with the specified base URL and calls
    // callback to notify the caller of ndt7 events.
    run: function(baseURL, testName, callback) {
      console.log('In run function')
      callback('starting', {Origin: 'client', Test: testName})
      let done = false
      let worker = new Worker('ndt7-' + testName + '.js')
      function finish() {
        console.log('Finish() is called')
        if (!done) {
          done = true
          if (callback !== undefined) {
            callback('complete', {Origin: 'client', Test: testName})
          }
        }
      }
      worker.onmessage = function (ev) {
        if (ev.data === null) {
          console.log('ev.data is null')
          finish()
          return
        }
        console.log('worker received message')
        callback('measurement', ev.data)
      }
      // Kill the worker after the timeout. This force the browser to
      // close the WebSockets and prevent too-long tests.
      setTimeout(function () {
        console.log('SetTimeout terminate worker')
        worker.terminate()
        finish()
      }, 14000)
      worker.postMessage({
        href: baseURL,
      })
    }
  }
}())
