app.directive('nvipLoginPanel', function() {
	
	return {
		link: function (scope, elem, attrs) {
			
		}, 
		restrict: 'E',
		scope: {
		},
		template:
		`<div class="nvip-login-panel container" ng-controller="LoginController as LoginCtrl">
				<div class="row justify-content-center">
					<div id="loginPanel" class="login-panel" ng-hide="isLoggedIn()" ng-controller="LoginController as loginCtrl">
										
						<div class="login-form-header col-11">
							<p class="login-header">
								NVIP Login
								<i class="fa fa-times" aria-hidden="true" style="float:right" onclick="closeLogin()"></i>
							</p>
							<p id="loginMessage" class="login-message">
								Login is Required
							</p>
						</div>
						
						<form id="loginForm" class="col-11 nvip-login-form" name="form" ng-submit="login()" role="form">
						    <div class="form-group col-12">
						        <label for="username">Username</label>
						        <i class="fa fa-key"></i>
						        <input type="text" name="username" id="username" class="form-control" ng-model="credentials.username" required />
						        <span ng-show="form.username.$dirty && form.username.$error.required" class="help-block">Username is required</span>
						    </div>
						    <div class="form-group col-12">
						        <label for="password">Password</label>
						        <i class="fa fa-lock"></i>
						        <input type="password" name="password" id="password" class="form-control" ng-model="credentials.password" required />
						    </div>
						    <div class="form-actions col-12">
						        <button class="login-submit-button btn btn-danger" type="submit" style="margin-left:2em" ng-click="clearListener()" ng-disabled="form.$invalid || dataLoading">Login</button>
						        <img ng-if="dataLoading" src="data:image/gif;base64,R0lGODlhEAAQAPIAAP///wAAAMLCwkJCQgAAAGJiYoKCgpKSkiH/C05FVFNDQVBFMi4wAwEAAAAh/hpDcmVhdGVkIHdpdGggYWpheGxvYWQuaW5mbwAh+QQJCgAAACwAAAAAEAAQAAADMwi63P4wyklrE2MIOggZnAdOmGYJRbExwroUmcG2LmDEwnHQLVsYOd2mBzkYDAdKa+dIAAAh+QQJCgAAACwAAAAAEAAQAAADNAi63P5OjCEgG4QMu7DmikRxQlFUYDEZIGBMRVsaqHwctXXf7WEYB4Ag1xjihkMZsiUkKhIAIfkECQoAAAAsAAAAABAAEAAAAzYIujIjK8pByJDMlFYvBoVjHA70GU7xSUJhmKtwHPAKzLO9HMaoKwJZ7Rf8AYPDDzKpZBqfvwQAIfkECQoAAAAsAAAAABAAEAAAAzMIumIlK8oyhpHsnFZfhYumCYUhDAQxRIdhHBGqRoKw0R8DYlJd8z0fMDgsGo/IpHI5TAAAIfkECQoAAAAsAAAAABAAEAAAAzIIunInK0rnZBTwGPNMgQwmdsNgXGJUlIWEuR5oWUIpz8pAEAMe6TwfwyYsGo/IpFKSAAAh+QQJCgAAACwAAAAAEAAQAAADMwi6IMKQORfjdOe82p4wGccc4CEuQradylesojEMBgsUc2G7sDX3lQGBMLAJibufbSlKAAAh+QQJCgAAACwAAAAAEAAQAAADMgi63P7wCRHZnFVdmgHu2nFwlWCI3WGc3TSWhUFGxTAUkGCbtgENBMJAEJsxgMLWzpEAACH5BAkKAAAALAAAAAAQABAAAAMyCLrc/jDKSatlQtScKdceCAjDII7HcQ4EMTCpyrCuUBjCYRgHVtqlAiB1YhiCnlsRkAAAOwAAAAAAAAAAAA=="/>
						        
						        
						        <a style="margin-left:8em" href="#/createaccount">
									<button class="login-submit-button btn btn-danger" ng-click="clearListener()">
										Register
									</button>
								</a>
						    </div>
						</form>
										
					</div>
				</div>
			</div>`
	};		
});			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			
			