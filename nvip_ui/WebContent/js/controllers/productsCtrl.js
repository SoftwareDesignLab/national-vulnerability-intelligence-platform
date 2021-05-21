app.controller('ProductsController', [ '$scope', '$timeout', '$rootScope', '$http', '$routeParams', '$cookieStore', function($scope, $timeout, $rootScope, $http, $routeParams, $cookieStore) {
     
    $http.defaults.headers.post["Content-Type"] = "application/x-www-form-urlencoded; charset=utf-8";
    
    /** Initialization code **/
    $scope.init();
    
    $scope.init = function () {
    	
    };   
    
	
    
} ]);
