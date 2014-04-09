var sampleProductCategories = new Array();

function BucketDetailViewModel(bucketID) {
    var self = this;
	
	// alert('/api/buckets/'+bucketID);
	//     self.bucketUri = '/api/buckets/'+bucketID;
	// alert(bucketUri);
    self.title = ko.observable();
    self.description = ko.observable();
    self.private = ko.observable();
    self.done = ko.observable();
    self.deadline = ko.observable();
    
    self.inputTodoTitle = ko.observable();
    self.inputTodoDue = ko.observable();
    
    self.todos = ko.observableArray();

    self.category = ko.observable();
    self.product = ko.observable();
    self.dueDate = ko.observable();
    
    self.ajax = function(uri, method, data) {
        var request = {
            url: uri,
            type: method,
            contentType: "application/json",
            accepts: "application/json",
            cache: false,
            dataType: 'json',
            async: false,
            data: JSON.stringify(data),
            error: function(jqXHR) {
                console.log("ajax error " + jqXHR.status);
            }
        };
        return $.ajax(request);
    }

    self.ajax('/api/getUserDday','GET').done(function(res) {
        sampleProductCategories = res.data;
    });

    self.updateTask = function(task, newTask) {
        var i = self.tasks.indexOf(task);
        self.tasks()[i].uri(newTask.uri);
        self.tasks()[i].title(newTask.title);
       	self.tasks()[i].description(newTask.description);
        self.tasks()[i].done(newTask.is_live);
		self.tasks()[i].private(newTask.is_private);
		self.tasks()[i].deadline(newTask.deadline.substr(0,10));
    }
	
    self.editTask = function() {
        self.edit(self.task, {
            title: self.title(),
            description: self.description() ,
            is_private: self.private(),
            is_live: self.done(),
            deadline: self.deadline()
        });
    }

    
    self.edit = function(task, data) {
        self.ajax('/api/buckets/'+bucketID, 'PUT', data).done(function(res) {
            self.updateTask(task, res.bucket);
        });
    }
	
	self.addTodo = function(){
		self.add({
			title: self.inputTodoTitle(),
			parent_id: bucketID,
            scope: 'TODO',
            deadline: self.inputTodoDue(),
            is_live: 'False'
		});
	}
	
	self.add = function(data) {
		self.ajax('/api/buckets/'+bucketID, 'POST', data).done(function(res) {
			self.todos.push({
                todotitle: ko.observable(res.bucket.title),
                tododone: ko.observable(res.bucket.is_live),
                tododeadline: ko.observable(res.bucket.deadline.substr(0,10))
			});
			// self.updateTask(task, res.todo);
		});
	}
	
    self.beginEdit = function() {
        self.ajax('/api/buckets/'+bucketID, 'GET').done(function(data){
            self.title(data.bucket.title);
            self.description(data.bucket.description);
            self.private(data.bucket.private);
            self.done(data.bucket.done);
            self.deadline(data.bucket.deadline);
            for (var i=0; i<data.todo.length; i++){
                self.todos.push({
                    todotitle: ko.observable(data.todo[i].title),
                    tododone: ko.observable(data.todo[i].is_live),
                    tododeadline: ko.observable(data.todo[i].deadline)
                });
            }
        });
    }

    self.beginEdit();
}
