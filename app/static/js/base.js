/**
 * Created by massinet on 2014. 3. 15..
 */

$(document).ready(function(){
    if(CheckAuthentication()){
        $('.loggedIn').show();
        $('.loggedOut').hide();
    } else {
        $('.loggedIn').hide();
        $('.loggedOut').show();
    }
    $("#logoutBtn").click(LogoutUser);
});

//var CheckAuthentication = function(){
//    var auth;
//    alert("2222");
//    if (localStorage.getItem('token')){
//        var auth_token = localStorage.getItem('token');
//        var hash = $.base64.encode(auth_token + ':unused');
//        $.ajax({
//            url: '/api/resource',
//            type: 'GET',
//            beforeSend: function(xhr){
//                xhr.setRequestHeader("Authorization", "Basic "+hash);
//            },
//            success: function(data){
//                localStorage.removeItem('id','email','username');
//                localStorage.setItem('id',data.data.id);
//                localStorage.setItem('username',data.data.username);
//                localStorage.setItem('email',data.data.email);
//                alert(data.data.is_admin);
//                if(data.data.is_admin == 0){
//                    $("#menuInquiryLink").attr('href','/inquiry/write');
//                } else {
//                    $("#menuInquiryLink").attr('href','/inquiry');
//                }
//                auth = true;
//            },
//            error: function(jqXHR){
//                console.log("ajax error " + jqXHR.status + ": " + jqXHR.description);
//                auth = false;
//            }
//        });
//    } else {
//        auth = false;
//    }
//    return auth;
//};
//
//var LogoutUser = function(){
//    if(CheckAuthentication()){
//        localStorage.clear();
//        alert("Bye!");
//    }
//    window.location = '/index';
//}