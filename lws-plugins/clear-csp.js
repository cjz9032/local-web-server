import EventEmitter from 'events'

class CSP extends EventEmitter {
  description() {
    return 'Support for modifying Content Security Policy (CSP) headers to remove restrictions.'
  }

  optionDefinitions() {
    return []
  }

  middleware(config) {
    const cspOptions = {
      'default-src': config.cspDefaultSrc || '*',
      'script-src': config.cspScriptSrc || "'unsafe-inline' *",
      'object-src': config.cspObjectSrc || '*',
      'base-uri': config.cspBaseUri || '*',
      'style-src': config.cspStyleSrc || "'unsafe-inline' *",
      'img-src': config.cspImgSrc || "* data:",
      'connect-src': config.cspConnectSrc || '*',
      'frame-src': config.cspFrameSrc || '*'
    }
    this.emit('verbose', 'middleware.csp.config', cspOptions)
  
    return async function (ctx, next) {
      const originalWriteHead = ctx.res.writeHead

      ctx.res.writeHead = function (statusCode, headers) {
        headers = headers || {};
        headers['content-security-policy'] = Object.entries(cspOptions)
          .map(([key, value]) => `${key} ${value}`)
          .join('; ')

        headers['content-security-policy'] = ''

        return originalWriteHead.call(this, statusCode, headers)
      }

      await next()
    }
  }
}

export default CSP
