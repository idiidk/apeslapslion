const debug = false
const client = new ClientJS()

function print(text, doAlert = false) {
  $('#log').append(`${text} <br>`)
  doAlert && alert(text)
}

function fail(status) {
  switch (status) {
    case 0:
      {
        print('This device is not compatible!', true)
        break
      }
  }
}

function testCompat() {
  const device = getProductName()
  const iOSVersion = getIOSVersion()

  return client.isMobileSafari() && device && iOSVersion && (iOSVersion[0] >= 11 && iOSVersion[1] < 4)
}

function doThings() {
  if (testCompat()) {
    const device = getProductName()
    const iOSVersion = getIOSVersion()

    print(`Device ${device} on iOS ${iOSVersion.toString().split(',').join('.')} is compatible!`)
    print(device)
    print('Downloading offsets...')

    fetch(`offsets/${device}-${iOSVersion.toString().split(',').join('.')}.json`)
      .then((res) => {
        if (res.status === 200) {
          res.json()
            .then((offsets) => {
              print('Done! Downloading exploit...')
              fetch('js/113.js')
                .then((res) => {
                  if (res.status === 200) {
                    res.text()
                      .then((exploitText) => {
                        print('Done! Running exploit...')
                        const exploit = new Function(exploitText)()
                        setTimeout(() => {
                          exploit(offsets, print, (wrapper) => {
                            
                          })
                        }, 100)
                      })
                  } else {
                    print('Fatal, exploit failed to download!', true)
                  }
                })
            })
        } else {
          print('Offsets for this device not found!', true)
        }
      })
  } else {
    fail(0)
  }
}

$('#go').click(doThings)

//Device detection (creds to @MTJailed)
function getGPU() {
  let GPU = null;
  let performance = window.performance || window.mozPerformance || window.msPerformance || window.webkitPerformance || {};
  let gpuElement = document.createElement('canvas');
  gpuElement.setAttribute('width', 0);
  gpuElement.setAttribute('height', 0);
  gpuElement.setAttribute('id', 'glcanvas');
  document.body.appendChild(gpuElement);
  let gl = document.getElementById('glcanvas').getContext('experimental-webgl');
  let renderInfo = null;
  try {
    renderInfo = gl.getExtension('WEBGL_debug_renderer_info');
    if (renderInfo) GPU = gl.getParameter(renderInfo.UNMASKED_RENDERER_WEBGL);
    document.getElementById('glcanvas').remove();
  } catch (ex) {
    alert(ex);
  }
  if (!GPU) GPU = false;
  return GPU;
}

function getIOSVersion() {
  let v = (navigator.appVersion).match(/OS (\d+)_(\d+)_?(\d+)?/)
  if (v === null) return []
  return [parseInt(v[1], 10), parseInt(v[2], 10)]
}

function getProductName() {
  let height = window.screen.height;
  let width = window.screen.width;
  let gpu = getGPU();

  if (gpu) gpu = gpu.split('Apple ');
  if (gpu.length > 1) {
    gpu = gpu[1].split(' GPU')[0];
  } else {
    gpu = false;
  }

  return client.getDevice() + '-' + gpu;
}