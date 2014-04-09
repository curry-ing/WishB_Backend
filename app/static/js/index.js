$(document).ready(function(){
    if(action=='logout'){
        LogoutUser();
    } else {
        if(CheckAuthentication()){
            $("#username").html(localStorage.getItem('username'));
            GetDreamList();
        } else {
            $("#username").html("GUEST");
        }
    }
});

var GetDreamList = function() {
    $.ajax({
        url: '/api/buckets/user/' + localStorage.getItem('id'),
        type: 'GET',
        beforeSend: function(xhr){
            var hash = $.base64.encode(localStorage.getItem('token') + ':unused');
            xhr.setRequestHeader("Authorization","Basic " + hash);
        },
        success: function(data){
            MakeDreamShelf(data.data);

        },
        error: function(jqXHR){
            console.log("ajax error " + jqXHR.status + ": " + jqXHR.description);
            return false;
        }
    });
}

var MakeDreamShelf = function(dreamList){
    console.log(dreamList);
    var width0=10, width1=10, width2=10, width3=10, width4=10, width5=10, width6=10;
    for (i=0; i<dreamList.length; i++){
        switch(dreamList[i].range){
            case '10':
                width1 = width1 + 190;
                node = $("#dreamBook").clone();
                $('.title',node).html(dreamList[i].title);
                node.show();
                $("#dreamBooks1").append(node);
                $("#dreamBooks1").css('width', width1+'px');
                if (dreamList[i].cvr_img_url){
                    $(node).css('background-image', 'url(' + dreamList[i].cvr_img_url + ')');
                };
                break;
            case '20':
                width2 = width2 + 190;
                node = $("#dreamBook").clone();
                $('.title',node).html(dreamList[i].title);
                node.show();
                $("#dreamBooks2").append(node);
                $("#dreamBooks2").css('width', width2+'px');
                if (dreamList[i].cvr_img_url){
                    $(node).css('background-image', 'url(' + dreamList[i].cvr_img_url + ')');
                };
                break;
            case '30':
                width3 = width3+ 190;
                node = $("#dreamBook").clone();
                $('.title',node).html(dreamList[i].title);
                node.show();
                $("#dreamBooks3").append(node);
                $("#dreamBooks3").css('width', width3+'px');
                if (dreamList[i].cvr_img_url){
                    $(node).css('background-image', 'url(' + dreamList[i].cvr_img_url + ')');
                };
                break;
            case '40':
                width4 = width4+ 190;
                node = $("#dreamBook").clone();
                $('.title',node).html(dreamList[i].title);
                node.show();
                $("#dreamBooks4").append(node);
                $("#dreamBooks4").css('width', width4+'px');
                if (dreamList[i].cvr_img_url){
                    $(node).css('background-image', 'url(' + dreamList[i].cvr_img_url + ')');
                };
                break;
            case '50':
                width5 = width5 + 190;
                node = $("#dreamBook").clone();
                $('.title',node).html(dreamList[i].title);
                node.show();
                $("#dreamBooks5").append(node);
                $("#dreamBooks5").css('width', width5+'px');
                if (dreamList[i].cvr_img_url){
                    $(node).css('background-image', 'url(' + dreamList[i].cvr_img_url + ')');
                };
                break;
            case '60':
                width6 = width6 + 190;
                node = $("#dreamBook").clone();
                $('.title',node).html(dreamList[i].title);
                node.show();
                $("#dreamBooks6").append(node);
                $("#dreamBooks6").css('width', width6+'px');
                if (dreamList[i].cvr_img_url){
                    $(node).css('background-image', 'url(' + dreamList[i].cvr_img_url + ')');
                };
                break;
            default:
                width0 = width0 + 190;
                node = $("#dreamBook").clone();
                $('.title',node).html(dreamList[i].title);
                node.show();
                $("#dreamBooks0").append(node);
                $("#dreamBooks0").css('width', width0+'px');
                if (dreamList[i].cvr_img_url){
                    $(node).css('background-image', 'url(' + dreamList[i].cvr_img_url + ')');
                };
                break;

        }
    }
}
//var CheckAuthentication = function(){
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
//                return true;
//            },
//            error: function(jqXHR){
//                console.log("ajax error " + jqXHR.status + ": " + jqXHR.description);
//                return false;
//            }
//        });
//        return true;
//    } else {
//        return false;
//    }
//}

//var LogoutUser = function(){
//    if(CheckAuthentication()){
//        localStorage.clear();
//        alert("Bye!");
//    }
//    window.location = '/index';
//}
