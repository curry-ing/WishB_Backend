/**
 * @author Ma Sunghoon
 */
 
function UsersViewModel(){
	var self = this;
	self.usersURI = '/api/users'
	self.users = ko.observableArray();
	
    self.ajax = function(uri, method, data) {
        var request = {
            url: uri,
            type: method,
            contentType: "application/json",
            accepts: "application/json",
            cache: false,
            dataType: 'json',
            data: JSON.stringify(data),
            error: function(jqXHR) {
                console.log("ajax error " + jqXHR.status);
            }
        };
        return $.ajax(request);
    }
	self.do = function() {
		self.ajax(self.usersURI, 'GET').done(function(data){
			for (var i = 0; i < data.users.length; i++) {		
				self.users.push({
					pic: ko.observable(data.users[i].pic),
					username: ko.observable(data.users[i].username),
					aboutme: ko.observable(data.users[i].about_me),
					following: ko.observable(data.users[i].is_following),
					Url: ko.observable('/userprofile/' + data.users[i].username),
					followuser: ko.observable('/follow/' + data.users[i].username),
					unfollowuser: ko.observable('/unfollow/' + data.users[i].username)
				});
			}
		});
	}

	self.do();
}