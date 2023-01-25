import { TestBed } from '@angular/core/testing';

import { VulnService } from './vuln.service';

describe('VulnService', () => {
  let service: VulnService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(VulnService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
