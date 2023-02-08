import { TestBed } from '@angular/core/testing';

import { SearchResultService } from './search-result.service';

describe('SearchResultService', () => {
  let service: SearchResultService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(SearchResultService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
