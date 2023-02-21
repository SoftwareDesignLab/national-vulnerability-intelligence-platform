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
