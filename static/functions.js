function MakePost(event) {
    event.preventDefault(); 
    window.location.href = "/makepost";
}


function welcome() {

    document.getElementById("paragraph").innerHTML += "<br/>This text was added by JavaScript 😅, please upload image in making the post. Enter chatroom for WebSocket connection";

    document.addEventListener("DOMContentLoaded", function() {
        const postButton = document.getElementById("post-button");
    
        postButton.addEventListener("click", MakePost);
    });
    
}
document.addEventListener("DOMContentLoaded", function() {
    const postButton = document.getElementById("post-button");
    
    postButton.addEventListener("click", MakePost);
    welcome();
});