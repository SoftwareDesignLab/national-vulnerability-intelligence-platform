'use strict';

customElements.define('compodoc-menu', class extends HTMLElement {
    constructor() {
        super();
        this.isNormalMode = this.getAttribute('mode') === 'normal';
    }

    connectedCallback() {
        this.render(this.isNormalMode);
    }

    render(isNormalMode) {
        let tp = lithtml.html(`
        <nav>
            <ul class="list">
                <li class="title">
                    <a href="index.html" data-type="index-link">angular-ui documentation</a>
                </li>

                <li class="divider"></li>
                ${ isNormalMode ? `<div id="book-search-input" role="search"><input type="text" placeholder="Type to search"></div>` : '' }
                <li class="chapter">
                    <a data-type="chapter-link" href="index.html"><span class="icon ion-ios-home"></span>Getting started</a>
                    <ul class="links">
                        <li class="link">
                            <a href="overview.html" data-type="chapter-link">
                                <span class="icon ion-ios-keypad"></span>Overview
                            </a>
                        </li>
                        <li class="link">
                            <a href="index.html" data-type="chapter-link">
                                <span class="icon ion-ios-paper"></span>README
                            </a>
                        </li>
                                <li class="link">
                                    <a href="dependencies.html" data-type="chapter-link">
                                        <span class="icon ion-ios-list"></span>Dependencies
                                    </a>
                                </li>
                                <li class="link">
                                    <a href="properties.html" data-type="chapter-link">
                                        <span class="icon ion-ios-apps"></span>Properties
                                    </a>
                                </li>
                    </ul>
                </li>
                    <li class="chapter modules">
                        <a data-type="chapter-link" href="modules.html">
                            <div class="menu-toggler linked" data-toggle="collapse" ${ isNormalMode ?
                                'data-target="#modules-links"' : 'data-target="#xs-modules-links"' }>
                                <span class="icon ion-ios-archive"></span>
                                <span class="link-name">Modules</span>
                                <span class="icon ion-ios-arrow-down"></span>
                            </div>
                        </a>
                        <ul class="links collapse " ${ isNormalMode ? 'id="modules-links"' : 'id="xs-modules-links"' }>
                            <li class="link">
                                <a href="modules/AppModule.html" data-type="entity-link" >AppModule</a>
                                    <li class="chapter inner">
                                        <div class="simple menu-toggler" data-toggle="collapse" ${ isNormalMode ?
                                            'data-target="#components-links-module-AppModule-d25d0c41dab4b788d95fe3ec824c3062a7dac2fd46ef8930be536d9b72fbc045528fb13c868da78d6624562beba7af7e03ce22b6eaae7e9dc88edd69f6f1e193"' : 'data-target="#xs-components-links-module-AppModule-d25d0c41dab4b788d95fe3ec824c3062a7dac2fd46ef8930be536d9b72fbc045528fb13c868da78d6624562beba7af7e03ce22b6eaae7e9dc88edd69f6f1e193"' }>
                                            <span class="icon ion-md-cog"></span>
                                            <span>Components</span>
                                            <span class="icon ion-ios-arrow-down"></span>
                                        </div>
                                        <ul class="links collapse" ${ isNormalMode ? 'id="components-links-module-AppModule-d25d0c41dab4b788d95fe3ec824c3062a7dac2fd46ef8930be536d9b72fbc045528fb13c868da78d6624562beba7af7e03ce22b6eaae7e9dc88edd69f6f1e193"' :
                                            'id="xs-components-links-module-AppModule-d25d0c41dab4b788d95fe3ec824c3062a7dac2fd46ef8930be536d9b72fbc045528fb13c868da78d6624562beba7af7e03ce22b6eaae7e9dc88edd69f6f1e193"' }>
                                            <li class="link">
                                                <a href="components/AboutComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >AboutComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/AppComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >AppComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/CreateAccountComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >CreateAccountComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/DailyComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >DailyComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/DailyVulnDropdownComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >DailyVulnDropdownComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/FooterComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >FooterComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/GoogleChartComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >GoogleChartComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/GoogleGaugeComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >GoogleGaugeComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/HeaderComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >HeaderComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/LoginPanelComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >LoginPanelComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/MainComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >MainComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/NvipChartComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >NvipChartComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/PrivacyComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >PrivacyComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/RecentComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >RecentComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/ReviewComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ReviewComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/SearchComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >SearchComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/SearchDropdownComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >SearchDropdownComponent</a>
                                            </li>
                                            <li class="link">
                                                <a href="components/VulnerabilityComponent.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >VulnerabilityComponent</a>
                                            </li>
                                        </ul>
                                    </li>
                                <li class="chapter inner">
                                    <div class="simple menu-toggler" data-toggle="collapse" ${ isNormalMode ?
                                        'data-target="#injectables-links-module-AppModule-d25d0c41dab4b788d95fe3ec824c3062a7dac2fd46ef8930be536d9b72fbc045528fb13c868da78d6624562beba7af7e03ce22b6eaae7e9dc88edd69f6f1e193"' : 'data-target="#xs-injectables-links-module-AppModule-d25d0c41dab4b788d95fe3ec824c3062a7dac2fd46ef8930be536d9b72fbc045528fb13c868da78d6624562beba7af7e03ce22b6eaae7e9dc88edd69f6f1e193"' }>
                                        <span class="icon ion-md-arrow-round-down"></span>
                                        <span>Injectables</span>
                                        <span class="icon ion-ios-arrow-down"></span>
                                    </div>
                                    <ul class="links collapse" ${ isNormalMode ? 'id="injectables-links-module-AppModule-d25d0c41dab4b788d95fe3ec824c3062a7dac2fd46ef8930be536d9b72fbc045528fb13c868da78d6624562beba7af7e03ce22b6eaae7e9dc88edd69f6f1e193"' :
                                        'id="xs-injectables-links-module-AppModule-d25d0c41dab4b788d95fe3ec824c3062a7dac2fd46ef8930be536d9b72fbc045528fb13c868da78d6624562beba7af7e03ce22b6eaae7e9dc88edd69f6f1e193"' }>
                                        <li class="link">
                                            <a href="injectables/ApiService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >ApiService</a>
                                        </li>
                                        <li class="link">
                                            <a href="injectables/AuthService.html" data-type="entity-link" data-context="sub-entity" data-context-id="modules" >AuthService</a>
                                        </li>
                                    </ul>
                                </li>
                            </li>
                            <li class="link">
                                <a href="modules/AppRoutingModule.html" data-type="entity-link" >AppRoutingModule</a>
                            </li>
                </ul>
                </li>
                        <li class="chapter">
                            <div class="simple menu-toggler" data-toggle="collapse" ${ isNormalMode ? 'data-target="#injectables-links"' :
                                'data-target="#xs-injectables-links"' }>
                                <span class="icon ion-md-arrow-round-down"></span>
                                <span>Injectables</span>
                                <span class="icon ion-ios-arrow-down"></span>
                            </div>
                            <ul class="links collapse " ${ isNormalMode ? 'id="injectables-links"' : 'id="xs-injectables-links"' }>
                                <li class="link">
                                    <a href="injectables/ApiService.html" data-type="entity-link" >ApiService</a>
                                </li>
                                <li class="link">
                                    <a href="injectables/AuthService.html" data-type="entity-link" >AuthService</a>
                                </li>
                                <li class="link">
                                    <a href="injectables/ChartsService.html" data-type="entity-link" >ChartsService</a>
                                </li>
                                <li class="link">
                                    <a href="injectables/CookieService.html" data-type="entity-link" >CookieService</a>
                                </li>
                                <li class="link">
                                    <a href="injectables/FuncsService.html" data-type="entity-link" >FuncsService</a>
                                </li>
                                <li class="link">
                                    <a href="injectables/SearchResultService.html" data-type="entity-link" >SearchResultService</a>
                                </li>
                                <li class="link">
                                    <a href="injectables/VulnService.html" data-type="entity-link" >VulnService</a>
                                </li>
                            </ul>
                        </li>
                    <li class="chapter">
                        <div class="simple menu-toggler" data-toggle="collapse" ${ isNormalMode ? 'data-target="#interfaces-links"' :
                            'data-target="#xs-interfaces-links"' }>
                            <span class="icon ion-md-information-circle-outline"></span>
                            <span>Interfaces</span>
                            <span class="icon ion-ios-arrow-down"></span>
                        </div>
                        <ul class="links collapse " ${ isNormalMode ? ' id="interfaces-links"' : 'id="xs-interfaces-links"' }>
                            <li class="link">
                                <a href="interfaces/AuthCredentials.html" data-type="entity-link" >AuthCredentials</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/Cookie.html" data-type="entity-link" >Cookie</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/CookieStore.html" data-type="entity-link" >CookieStore</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/CVSSScore.html" data-type="entity-link" >CVSSScore</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/HttpRequest.html" data-type="entity-link" >HttpRequest</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/HttpRequestOptions.html" data-type="entity-link" >HttpRequestOptions</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/Product.html" data-type="entity-link" >Product</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/SearchCriteria.html" data-type="entity-link" >SearchCriteria</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/Session.html" data-type="entity-link" >Session</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/SingleDatum.html" data-type="entity-link" >SingleDatum</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/VDO.html" data-type="entity-link" >VDO</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/Vulnerability.html" data-type="entity-link" >Vulnerability</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/VulnMap.html" data-type="entity-link" >VulnMap</a>
                            </li>
                            <li class="link">
                                <a href="interfaces/VulnMaps.html" data-type="entity-link" >VulnMaps</a>
                            </li>
                        </ul>
                    </li>
                    <li class="chapter">
                        <div class="simple menu-toggler" data-toggle="collapse" ${ isNormalMode ? 'data-target="#miscellaneous-links"'
                            : 'data-target="#xs-miscellaneous-links"' }>
                            <span class="icon ion-ios-cube"></span>
                            <span>Miscellaneous</span>
                            <span class="icon ion-ios-arrow-down"></span>
                        </div>
                        <ul class="links collapse " ${ isNormalMode ? 'id="miscellaneous-links"' : 'id="xs-miscellaneous-links"' }>
                            <li class="link">
                                <a href="miscellaneous/enumerations.html" data-type="entity-link">Enums</a>
                            </li>
                            <li class="link">
                                <a href="miscellaneous/typealiases.html" data-type="entity-link">Type aliases</a>
                            </li>
                            <li class="link">
                                <a href="miscellaneous/variables.html" data-type="entity-link">Variables</a>
                            </li>
                        </ul>
                    </li>
                        <li class="chapter">
                            <a data-type="chapter-link" href="routes.html"><span class="icon ion-ios-git-branch"></span>Routes</a>
                        </li>
                    <li class="chapter">
                        <a data-type="chapter-link" href="coverage.html"><span class="icon ion-ios-stats"></span>Documentation coverage</a>
                    </li>
                    <li class="divider"></li>
                    <li class="copyright">
                        Documentation generated using <a href="https://compodoc.app/" target="_blank">
                            <img data-src="images/compodoc-vectorise.png" class="img-responsive" data-type="compodoc-logo">
                        </a>
                    </li>
            </ul>
        </nav>
        `);
        this.innerHTML = tp.strings;
    }
});