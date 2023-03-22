/**
 * Copyright 2023 Rochester Institute of Technology (RIT). Developed with
 * government support under contract 70RSAT19CB0000020 awarded by the United
 * States Department of Homeland Security.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
import { Injectable } from '@angular/core';
import { Session } from '../Auth/auth-service.service';

/* Related Interfaces */
export interface Cookie {
  key: string;
  value: string;
}

export interface CookieStore extends Record<string, Session>{
  [key: string]: Session;
}

@Injectable({
  providedIn: 'root'
})
export class CookieService {
  /** application store for browser cookies */
  private cookies: CookieStore = {}

  constructor() {
    this.init()
  }

  /** load broswer cookies on application init */
  private init() {
    let cookiesFromBrowser: string[] = document.cookie.split(";")
    cookiesFromBrowser.forEach((cookiesString) => {
      try {
        const [key, value] = cookiesString.split("=");
        this.cookies[key] = JSON.parse(value);
      } catch (e: unknown) {
        console.log(e);
      }

    })
  }

  /** getter for specific cookie in CookieStore */
  get(cookieKey: string) {
    return cookieKey in this.cookies ? this.cookies[cookieKey] : {} as Session;
  }

  /** store a browser cookie */
  put(cookieKey: string, session: Session) {
    this.cookies[cookieKey] = session;
    document.cookie = `${cookieKey}=${JSON.stringify(session)};`;
  }

  /** remove a broswer cookie for a given session */
  remove(cookieKey: string) {
    this.cookies[cookieKey] = {} as Session;
    document.cookie = `${cookieKey}={}`;
  }

}
