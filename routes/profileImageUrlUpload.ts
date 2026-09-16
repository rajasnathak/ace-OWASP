/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns/promises'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrReservedIpv4 (ip: string): boolean {
  const parts = ip.split('.').map(Number)
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return true
  }
  const [a, b, c, d] = parts

  if (a === 0) return true
  if (a === 10) return true
  if (a === 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 192 && b === 0 && c === 0) return true
  if (a === 192 && b === 0 && c === 2) return true
  if (a === 198 && b === 51 && c === 100) return true
  if (a === 203 && b === 0 && c === 113) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a >= 224) return true

  return false
}

function isPrivateOrReservedIpv6 (ip: string): boolean {
  const clean = ip.toLowerCase()
  if (clean === '::1' || clean === '::' || clean === '0:0:0:0:0:0:0:0' || clean === '0:0:0:0:0:0:0:1') {
    return true
  }
  if (clean.startsWith('fc') || clean.startsWith('fd')) {
    return true
  }
  if (/^fe[89ab]/i.test(clean)) {
    return true
  }
  if (clean.startsWith('ff')) {
    return true
  }
  return false
}

function isPrivateOrReservedIp (ip: string): boolean {
  if (ip.startsWith('::ffff:')) {
    const ipv4Part = ip.slice(7)
    if (net.isIPv4(ipv4Part)) {
      return isPrivateOrReservedIpv4(ipv4Part)
    }
  }
  if (net.isIPv4(ip)) {
    return isPrivateOrReservedIpv4(ip)
  }
  if (net.isIPv6(ip)) {
    return isPrivateOrReservedIpv6(ip)
  }
  return true
}

async function isSafeUrl (urlString: string): Promise<boolean> {
  if (typeof urlString !== 'string' || !urlString.trim()) {
    return false
  }

  let parsedUrl: URL
  try {
    parsedUrl = new URL(urlString)
  } catch {
    return false
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return false
  }

  const hostname = parsedUrl.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (!hostname) {
    return false
  }

  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    return false
  }

  if (net.isIP(hostname)) {
    return !isPrivateOrReservedIp(hostname)
  }

  try {
    const addresses = await dns.lookup(hostname, { all: true })
    if (!addresses || addresses.length === 0) {
      return false
    }
    for (const record of addresses) {
      if (isPrivateOrReservedIp(record.address)) {
        return false
      }
    }
  } catch {
    return false
  }

  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!(await isSafeUrl(url))) {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
