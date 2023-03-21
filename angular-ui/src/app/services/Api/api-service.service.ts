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
import {
  HttpClient,
  HttpContext,
  HttpHeaders,
  HttpParams,
  HttpResponse,
} from '@angular/common/http';
import { Observer } from 'rxjs';
import { AuthCredentials } from '../Auth/auth-service.service';
import { Routes } from './api_routes';

/* Related Interfaces */

export interface HttpRequest {
  url: string;
  options: HttpRequestOptions;
}

export interface HttpRequestOptions {
  method: string;
  headers?: HttpHeaders | { [header: string]: string | string[] } | undefined;
  context?: HttpContext | undefined;
  params?: HttpRequestParams;
  reportProgress?: boolean;
  withCredentials?: boolean;
}

export type HttpRequestParams =
  | HttpParams
  | {
      [param: string]:
        | string
        | number
        | boolean
        | ReadonlyArray<string | number | boolean>;
    };

export type ApiRequestObserver =
  | Partial<Observer<Object>>
  | ((value: Object) => void);


// export interface CVEDetailsRequest {
//   cveId: string; // TODO: figure out the actual type of this
//   username: string;
//   token: string;
// }
// export interface CVESearchRequest {
//   username: string;
//   token: string;
//   searchDate: string; // TODO: find real type
//   crawled: boolean;
//   rejected: boolean;
//   accepted: boolean;
//   reviewed: boolean;
// }
// export interface CVEUpdateRequest {
//   atomicUpdate: boolean;
//   username: string;
//   token: string;
//   statusID: string; // TODO: find real type
//   vulnID: string; // TODO: find real type
//   info: string; // TODO: find real type
//   tweet: boolean;
// }

@Injectable({
  providedIn: 'root',
})
export class ApiService {
  private GET_OPTIONS: HttpRequestOptions = {
    method: 'GET',
  };

  constructor(private httpClient: HttpClient) {}

  login(credentials: AuthCredentials) {
    //callback: ApiRequestObserver) {
    const request = this.httpClient.get(
      Routes.login,
      this.injectGetParameters({ ...credentials })
    );
    // request.subscribe(callback)
    return request;
  }

  createAccount(credentials: object, callback: ApiRequestObserver) {
    const body = JSON.stringify(credentials);
    this.httpClient
      .post(Routes.login, body, {
        headers: {
          'Content-Type': 'application/json',
        },
        params: {
          createUser: true,
        },
      })
      .subscribe(callback);
  }

  countGraphs(callback: ApiRequestObserver) {
    this.httpClient
      .get(Routes.main, this.injectGetParameters({ countGraphs: 'all' }))
      .subscribe(callback);
  }

  
  cveSearch(searchRequest: any) {
    return this.httpClient
    .get(Routes.search, this.injectGetParameters({ ...searchRequest }))
  }
  
  
  // For Review page, which is currently unused
  
  // cveDetails(detailRequst: CVEDetailsRequest, callback: ApiRequestObserver) {
  //   this.httpClient
  //     .get(Routes.review, this.injectGetParameters({ ...detailRequst }))
  //     .subscribe(callback);
  // }
  // cveUpdateAtomic(
  //   updateRequest: CVEUpdateRequest,
  //   cveDescription: string,
  //   callback: ApiRequestObserver
  // ) {
  //   this.httpClient.post(Routes.review, cveDescription, {
  //     headers: {
  //       'Content-Type': 'Text/plain',
  //     },
  //     params: {
  //       ...updateRequest,
  //     },
  //   });
  // }

  // cveUpdateComplex(updateRequest: CVEUpdateRequest) {}

  vulnServlet(daily: boolean, dateRange: number) {
    return this.httpClient.get(
      Routes.vulnerability,
      this.injectGetParameters({ daily: daily, dateRange: dateRange })
    );
  }

  vulnServGetByID(id: string, username: string, token: string) {
    return this.httpClient.get(
      Routes.vulnerability,
      this.injectGetParameters({
        token: token,
        username: username, 
        vulnId: id 
      })
    );
  }

  searchInfo(username: string, token: string) {
    return this.httpClient.get(
      Routes.search,
      this.injectGetParameters({ 
        searchInfo: true,
        token: token,
        username: username 
      })
    );
  }

  private injectGetParameters(params: HttpRequestParams) {
    return { ...this.GET_OPTIONS, params: params };
  }
}
