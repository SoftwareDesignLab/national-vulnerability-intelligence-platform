import { Injectable } from '@angular/core';
/** Search Result Service */
@Injectable({
  providedIn: 'root'
})
export class SearchResultService {
  
  /** Persist search servlet results on route change */
  searchResults: Array<any> = [];

  /**
   * get persisted search results, if any
   * @returns Array of CVE objects stored
   */
  getSearchResults() {
    return this.searchResults
  }

  /**
   * store search results for viewing when coming back to search page
   * again in the same session
   * @param newRes Array of CVE objects to be stored for next time use
   */
  setSearchResults(newRes: Array<any>) {
    this.searchResults = newRes;
  }

}
