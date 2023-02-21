import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { AboutComponent } from './pages/about/about.component';
import { CreateAccountComponent } from './pages/create-account/create-account.component';
import { DailyComponent } from './pages/daily/daily.component';
import { MainComponent } from './pages/main/main.component';
import { PrivacyComponent } from './pages/privacy/privacy.component';
import { RecentComponent } from './pages/recent/recent.component';
import { ReviewComponent } from './pages/review/review.component';
import { SearchComponent } from './pages/search/search.component';
import { VulnerabilityComponent } from './pages/vulnerability/vulnerability.component';

const routes: Routes = [
  { path: '', component: MainComponent },
  { path: 'about', component: AboutComponent },
  { path: 'review', component: ReviewComponent },
  { path: 'recent', component: RecentComponent },
  { path: 'daily', component: DailyComponent },
  { path: 'privacy', component: PrivacyComponent },
  { path: 'search', component: SearchComponent },
  { path: 'vulnerability/:id', component: VulnerabilityComponent },
  { path: 'createaccount', component: CreateAccountComponent }
];

@NgModule({
  imports: [RouterModule.forRoot(routes)],
  exports: [RouterModule],
})
export class AppRoutingModule {}
