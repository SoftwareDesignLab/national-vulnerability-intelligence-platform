# NVIP Angular UI Requirements
    - Node 18.13.0
    - Angular 15.1.0
    - Tomcat web backend up and running
# NVIP Angular UI Steps
    - Ensure you have Node 18.13.0
    - Ensure you have Angular CLI installed: npm install -g @angular/cli
    - cd angular-ui
    - npm install
    - ng serve (or npm start)
    - Visit localhost:4200
    - Note: Proxy assumes you have a local Tomcat instance (localhost:8080) of the nvip war deployed to /nvip_ui-1.0

# Generate and View UI documentation
    The application uses Compodoc (https://compodoc.app/guides/getting-started.html) to generate static documentation of the frontend,
    very similarly to javadocs.
    View extensive angular frontend documenation and coverage by runnning 'npm run compodoc' and visiting `localhost:4201`.
    View in depth graphs, charts, and coverage by navigating to Module, Routes, and Documentation coverage pages respectively

# AngularUi

This project was generated with [Angular CLI](https://github.com/angular/angular-cli) version 15.1.2.

## Development server

Run `ng serve --configuration=development` for a dev server. Navigate to `http://localhost:4200/`. The application will automatically reload if you change any of the source files.

## Run Server w/ Prod. setup

To test against Production environment locally, run `ng serve --configuration=production` or `ng serve --proxy-config proxy.conf.json` and navigate to `localhost:4200`.
Here, API calls will be forwarded to AWS S3 URL instead of local TomCat instance.

## Code scaffolding

Run `ng generate component component-name` to generate a new component. You can also use `ng generate directive|pipe|service|class|guard|interface|enum|module`.

## Build

Run `ng build` to build the project. The build artifacts will be stored in the `dist/` directory.

## Running unit tests

Run `ng test` to execute the unit tests via [Karma](https://karma-runner.github.io).

## Running end-to-end tests

Run `ng e2e` to execute the end-to-end tests via a platform of your choice. To use this command, you need to first add a package that implements end-to-end testing capabilities.

## Further help

To get more help on the Angular CLI use `ng help` or go check out the [Angular CLI Overview and Command Reference](https://angular.io/cli) page.
