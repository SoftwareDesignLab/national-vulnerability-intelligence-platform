import { TestBed } from '@angular/core/testing';

import { FuncsService } from './funcs.service';

describe('FuncsService', () => {
  let service: FuncsService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(FuncsService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
