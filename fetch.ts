let password = '';
let passwordHeader = 'x-fetch-password';
let excludeHeadersPrefix = ['cf-', 'x-forwarded-proto', 'x-real-ip', 'true-client-ip', 'x-forwarded-for', passwordHeader];

async function handleFetch(request: Request): Promise<Response> {
    let url = new URL(request.url);
    let requestUrl = url.pathname + url.search;
    requestUrl = requestUrl.replace(/^\/*(https?:)(\/*)/, '$1//');
    let newHeaders = new Headers();
    for (let [key, value] of request.headers.entries()) {
        let exclude = false;
        for (let excludePrefix in excludeHeadersPrefix) {
            if (key.toLowerCase().startsWith(excludePrefix)) {
                exclude = true;
                break;
            }
        }
        if (!exclude) newHeaders.append(key, value);
    }
    return fetch(requestUrl, request);
}

function validateRequest(request: Request): boolean {
    if (password && password !== request.headers.get(passwordHeader)) {
        return false;
    }
    let url = new URL(request.url);
    if (url.pathname.startsWith('/http:/') || url.pathname.startsWith('/https:/')) {
        return true;
    }
    return false;
}

async function handle(request: Request): Promise<Response> {
    console.log(request.url);
    if (validateRequest(request)) {
        return handleFetch(request);
    } else {
        return new Response(request.headers.get('x-real-ip') || "OK");
    }
}

export default {
    fetch(request: Request) {
        return handle(request);
    }
}