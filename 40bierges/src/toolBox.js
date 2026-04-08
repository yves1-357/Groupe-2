const readCookie = (cname) => {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(';');
    for (var i = 0; i < ca.length; i++) {
        var c = ca[i];
        while (c.charAt(0) === ' ') {
            c = c.substring(1);
        }
        if (c.indexOf(name) === 0) {
            return c.substring(name.length, c.length)
        }
    }
    return undefined;
}

const checkIfConnected = () => {
    let token = readCookie("Token")
    if (token !== undefined) {
        return true;
    }
    return false;
}

const tools = { readCookie, checkIfConnected };
export default tools;