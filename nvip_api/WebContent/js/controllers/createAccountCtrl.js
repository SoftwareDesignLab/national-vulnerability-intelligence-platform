app.controller('CreateAccountController', ['$scope', '$rootScope', '$location', 'AUTH_EVENTS', 'AuthService', '$http', '$cookieStore', 
	function ($scope, $rootScope, $location, AUTH_EVENTS, AuthService, $http, $cookieStore) {
	// TODO: Clear credentials after login successful OR remove need for scope object when passing data
	$scope.credentials = {
			username: '',
			password: '',
			repeatPassword: '',
			fname: '',
			lname: '',
			email: ''
	};
	
	$scope.createAccount = function () {
		
		if ($scope.credentials.password != $scope.credentials.repeatPassword){
			document.getElementById("registrationMessage").innerText = "Passwords don't match";
			document.getElementById("registrationMessage").style.display = "block";
			document.getElementById("regForm").style.marginTop = "6em";
			return;
		}

		$http({
            url : 'loginServlet',
            method : "POST", 
            headers: {
                'Content-Type': 'application/json',
              },
            params : {createUser:true},
            data : JSON.stringify($scope.credentials),
        }).then(function(response) {
                       
        	alert("Your account is Created!");

            
        }, function(response) {
            console.log("Failure -> " + response.data);
            
            document.getElementById("registrationMessage").innerText = response.data;
            document.getElementById("registrationMessage").style.display = "block";
			document.getElementById("regForm").style.marginTop = "6em";
			
        });
	};

	
	$scope.isLoggedIn = function() {
  		return AuthService.isAuthenticated();
  	}
	
	$scope.getUsername = function() {
		var user = $cookieStore.get('nvip_user');
		
		if (user != null){
			return user.username;
		}
		
		return null;
	}
	
	$scope.getFirstName = function() {
		var user = $cookieStore.get('nvip_user');
		
		if (user != null){
			return user.firstname;
		}
		
		return null;
	}
	
	$scope.logOut = function() {
		$cookieStore.remove('nvip_user');
		window.location.reload();
		return null;
	}
	
	$scope.getUserRole = function() {
		var user = $cookieStore.get('nvip_user');
		
		if (user != null){
			return user.role;
		}
		
		return null;
	}
}]);