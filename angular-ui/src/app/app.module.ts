import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { HttpClientModule } from "@angular/common/http";
import { FormsModule } from '@angular/forms';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { HeaderComponent } from './components/header/header.component';
import { FooterComponent } from './components/footer/footer.component';
import { MainComponent } from './pages/main/main.component';
import { AboutComponent } from './pages/about/about.component';
import { ReviewComponent } from './pages/review/review.component';
import { LoginPanelComponent } from './components/login-panel/login-panel.component';
import { RecentComponent } from './pages/recent/recent.component';
import { CreateAccountComponent } from './pages/create-account/create-account.component';
import { DailyComponent } from './pages/daily/daily.component';
import { PrivacyComponent } from './pages/privacy/privacy.component';
import { SearchComponent } from './pages/search/search.component';
import { VulnerabilityComponent } from './pages/vulnerability/vulnerability.component';
import { DailyVulnDropdownComponent } from './components/daily-vuln-dropdown/daily-vuln-dropdown.component';
import { ApiService } from './services/Api/api-service.service';
import { AuthService } from './services/Auth/auth-service.service';
import { FontAwesomeModule } from '@fortawesome/angular-fontawesome';
import { NgxChartsModule } from '@swimlane/ngx-charts';
import { NvipChartComponent } from './components/nvip-chart/nvip-chart.component';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { SearchDropdownComponent } from './components/search-dropdown/search-dropdown.component';
import { GoogleChartComponent } from './components/google-chart/google-chart.component';
import { GoogleGaugeComponent } from './components/google-chart/google-gauge.component';
@NgModule({
  declarations: [
    AppComponent,
    HeaderComponent,
    FooterComponent,
    MainComponent,
    AboutComponent,
    ReviewComponent,
    LoginPanelComponent,
    RecentComponent,
    CreateAccountComponent,
    DailyComponent,
    PrivacyComponent,
    SearchComponent,
    VulnerabilityComponent,
    DailyVulnDropdownComponent,
    NvipChartComponent,
    SearchDropdownComponent,
    GoogleChartComponent,
    GoogleGaugeComponent
  ],
  imports: [
    BrowserModule,
    AppRoutingModule,
    HttpClientModule,
    FontAwesomeModule,
    FormsModule,
    NgxChartsModule,
    BrowserAnimationsModule
  ],
  providers: [ApiService, AuthService],
  bootstrap: [AppComponent]
})
export class AppModule { }
