////////////////////////
// START lib/edgeauth.js
////////////////////////
import { crypto } from 'crypto';
import {TextEncoder} from 'encoding';

class EdgeAuth {
    constructor(options) {
        this.options = options

        if (!this.options.tokenName) {
            this.options.tokenName = '__token__'
        }

        if (!this.options.key) {
            throw new Error('key must be provided to generate a token.')
        }

        if (this.options.escapeEarly === undefined) {
            this.options.escapeEarly = false
        }

        if (!this.options.fieldDelimiter) {
            this.options.fieldDelimiter = '~'
        }

        if (!this.options.aclDelimiter) {
            this.options.aclDelimiter = '!'
        }

        if (this.options.verbose === undefined) {
            this.options.verbose = false
        }
    }

    _escapeEarly(text) {
        if (this.options.escapeEarly) {
            text = encodeURIComponent(text)
                .replace(/[~'*]/g, 
                    function(c) {
                        return '%' + c.charCodeAt(0).toString(16)
                    }
                )
            var pattern = /%../g
            text = text.replace(pattern, function(match) {
                return match.toLowerCase()
            })
        } 
        return text
    }

	_computeHMACFromHexKey(data, key) {
	  const hexToBytes = hex =>
	    new Uint8Array(key.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
	  const keyBytes = hexToBytes(key);

	  const encoder = new TextEncoder();
	  const dataBytes = encoder.encode(data);

	  return crypto.subtle.importKey(
	    "raw",
	    keyBytes,
	    { name: "HMAC", hash: "SHA-256" },
	    false,
	    ["sign"]
	  )
	  .then(cryptoKey => crypto.subtle.sign("HMAC", cryptoKey, dataBytes))
	  .then(signature => {
	    const hmacHex = Array.from(new Uint8Array(signature))
	      .map(b => b.toString(16).padStart(2, "0"))
	      .join("");
	    return hmacHex;
	  });
	}

    async _generateToken(path, isUrl) {
        var startTime = this.options.startTime
        var endTime = this.options.endTime

        if (typeof startTime === 'string' && startTime.toLowerCase() === 'now') {
            startTime = parseInt(Date.now() / 1000)
        } else if (startTime) {
            if (typeof startTime === 'number' && startTime <= 0) {
                throw new Error('startTime must be number ( > 0 ) or "now"')
            }
        }

        if (typeof endTime === 'number' && endTime <= 0) {
            throw new Error('endTime must be number ( > 0 )')
        }

        if (typeof this.options.windowSeconds === 'number' && this.options.windowSeconds <= 0) {
            throw new Error('windowSeconds must be number( > 0 )')
        }

        if (!endTime) {
            if (this.options.windowSeconds) {
                if (!startTime) {
                    startTime = parseInt(Date.now() / 1000)
                } 
                endTime = parseInt(startTime) + parseInt(this.options.windowSeconds)
            } else {
                throw new Error('You must provide endTime or windowSeconds')
            }
        }

        if (startTime && (endTime < startTime)) {
            throw new Error('Token will have already expired')
        }

        var hashSource = []
        var newToken = []

        if (this.options.ip) {
            newToken.push("ip=" + this._escapeEarly(this.options.ip))
        }

        if (this.options.startTime) {
            newToken.push("st=" + startTime)
        }
        newToken.push("exp=" + endTime)

        if (!isUrl) {
            newToken.push("acl=" + path)
        }

        if (this.options.sessionId) {
            newToken.push("id=" + this._escapeEarly(this.options.sessionId))
        }

        if (this.options.payload) {
            newToken.push("data=" + this._escapeEarly(this.options.payload))
        }

        hashSource = newToken.slice()

        if (isUrl) {
            hashSource.push("url=" + this._escapeEarly(path))
        }

        if (this.options.salt) {
            hashSource.push("salt=" + this.options.salt)
        }

        var data = hashSource.join(this.options.fieldDelimiter)

        const hmac = await this._computeHMACFromHexKey(data, this.options.key)
        
        newToken.push("hmac=" + hmac)
                
        return newToken.join(this.options.fieldDelimiter)
    }


    generateACLToken(acl) {
        if (!acl) {
            throw new Error('You must provide acl')
        } else if(acl.constructor == Array) {
            acl = acl.join(this.options.aclDelimiter)
        }

        return this._generateToken(acl, false)
    }

    generateURLToken(url) {
        if (!url) {
            throw new Error('You must provide url')
        }
        return this._generateToken(url, true)
    }
}

export { EdgeAuth }; 
