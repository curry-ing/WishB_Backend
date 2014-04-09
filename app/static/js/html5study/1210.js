document.getElementById("findChecked").onclick = function () {
    var selected = document.querySelectorAll("*:checked");
    var result = "Selected boxes are: ";

    for (var i = 0; i < selected.length; i++) {
        result += (selected[i].name);
        if (i < selected.length - 1) result += ", ";
    }
    document.getElementById("checkedResult").innerHTML = result;
};

function drawdiagonal(){
    var canvas = document.getElementById("diagonal");
    var ctx=canvas.getContext('2d');
    var ctx2=canvas.getContext('2d');
    var ctx3=canvas.getContext('2d');

    ctx.strokeStyle = "Green";
    ctx.beginPath();
    ctx.moveTo(100,100);
    ctx.lineTo(200,200);
    ctx.stroke();

    ctx2.fillStyle = "Yellow";
    ctx2.strokeStyle = "Blue";
    ctx2.fillRect(220,190,60,90);
    ctx2.strokeRect(220,190,60,90);

    ctx3.strokeRect(300,300,90,90);
}

var bark = new Image();
bark.src = "../static/img/html5study/bark.jpg";

bark.onload = function() {
    drawTrails();
}

var gravel = new Image();
gravel.src = "../static/img/html5study/gravel.jpg";
gravel.onload = function() {
    drawTrails();
}

function createCanopyPath(context){
   //Draw the tree canopy
    context.beginPath();

    context.moveTo(-25,-50);
    context.lineTo(-10,-80);
    context.lineTo(-20,-80);
    context.lineTo(-5,-110);
    context.lineTo(-15,-110);

    //Top of the Tree
    context.lineTo(0,-140);
    context.lineTo(15,-110);
    context.lineTo(5,-110);
    context.lineTo(20,-80);
    context.lineTo(10,-80);
    context.lineTo(25,-50);

    context.closePath();
}

function drawTree(context){
    context.save();
    context.transform(1,0,-0.5,1,0,0);

    context.scale(1,0.6);
    context.fillStyle = 'rgba(0,0,0,0.2)';
    context.fillRect(-5,-50,10,50);
    createCanopyPath(context);
    context.fill();
    context.restore();

    var trunkGradient = context.createLinearGradient(-5, -50, 5, -50);
    trunkGradient.addColorStop(0, '#663300');
    trunkGradient.addColorStop(0.4, '#996600');
    trunkGradient.addColorStop(1, '#552200');
    context.fillStyle = trunkGradient;
    context.fillRect(-5, -50, 10, 50);

    var canopyShadow = context.createLinearGradient(0, -50, 0, 0);
    canopyShadow.addColorStop(0, 'rgba(0, 0, 0, 0.5)');
    canopyShadow.addColorStop(0.2, 'rgba(0, 0, 0, 0.0)');
    context.fillStyle = canopyShadow;
    context.fillRect(-5, -50, 10, 50);

    createCanopyPath(context);

    context.lineWidth = 4;
    context.lineJoin = 'round';
    context.strokeStyle = '#663300';
    context.stroke();

    context.fillStyle = '#339900';
    context.fill();
}

function drawTrails(){
    var canvas = document.getElementById('trails');
    var context = canvas.getContext('2d');

    context.save();
    context.translate(130,250);

    drawTree(context);
    context.restore();

    context.save();
    context.translate(260,500);
    context.scale(2,2);
    drawTree(context);
    context.restore();

//    createCanopyPath(context);
//
//    //Increase the line width
//    context.lineWidth = 4;
//    // Round the coners at path joints
//    context.lineJoin = 'round';
//    // Change the color brown
//    context.strokeStyle='#663300';
//
//    context.stroke();
//
//    context.fillStyle = '#339900';
//    context.fill();
//
////    context.drawImage(bark, -5, -50, 10, 50);
//
////    context.fillStyle = '#663300';
////    context.fillRect(-5, -50, 10, 50);
//    var trunkGradient = context.createLinearGradient(-5, -50, 5, -50);
//    trunkGradient.addColorStop(0, '#663300');
//    trunkGradient.addColorStop(0.4, '#996600');
//    trunkGradient.addColorStop(1, '#552200');
//
//    context.fillStyle = trunkGradient;
//    context.fillRect(-5, -50, 10, 50);
//
//    var canopyShadow = context.createLinearGradient(0, -50, 0, 0);
//    canopyShadow.addColorStop(0, 'rgba(0,0,0,0.5)');
//    canopyShadow.addColorStop(0.2, 'rgba(0,0,0,0.0)');
//
//    context.fillStyle = canopyShadow;
//    context.fillRect(-5, -50, 10, 50);
//
//
//    context.restore();

    context.save();

    context.translate(-10, 350);
    context.beginPath();

    context.moveTo(0, 0);
    context.quadraticCurveTo(170,-50,260,-190);
    context.quadraticCurveTo(310,-250,410,-250);

//    context.strokeStyle = '#663300';
    context.strokeStyle = context.createPattern(gravel, 'repeat');
    context.lineWidth = 20;
    context.stroke();

    context.restore();

    context.save();
    context.font = "60px impact";
    context.fillStyle = '#996600';
    context.textAlign = 'center';

    context.shadowColor = 'rgba(0,0,0,0.2)';
    context.shadowOffsetX = 15;
    context.shadowOffsetY = -10;

    context.shadowBlur = 2;
    context.fillText('Happy Trails!', 200, 60, 400);
    context.restore();

}



window.addEventListener("load", drawdiagonal, true);
window.addEventListener("load", drawTrails, true);
