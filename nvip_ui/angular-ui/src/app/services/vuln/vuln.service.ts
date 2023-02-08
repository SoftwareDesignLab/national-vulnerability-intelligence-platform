import { Injectable } from '@angular/core';
import { ApiService } from '../Api/api-service.service';

@Injectable({
  providedIn: 'root'
})
export class VulnService {
  
  constructor(private api: ApiService) { }

  onRecentInit() {
    return this.api.vulnServlet(true, 10)
  }

  getByID(id: string, username: string, token: string) {
    return this.api.vulnServGetByID(id, username, token);
  }

  searchInfo(username: string, token: string) {
    return this.api.searchInfo(username, token);
  }
}
