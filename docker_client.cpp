#include "docker_client.hpp"

#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include <memory>
//#include <iostream>
#include <system_error>
#include <errno.h>

using namespace cocaine::docker;

endpoint_t::endpoint_t() {
    // pass
}

endpoint_t::endpoint_t(const tcp_endpoint_t& e) :
    m_value(e)
{
    // pass
}

endpoint_t::endpoint_t(const unix_endpoint_t& e) :
    m_value(e)
{
    // pass
}

endpoint_t
endpoint_t::from_string(const std::string& endpoint) {
    if (endpoint.compare(0, 6, "tcp://") == 0) {
        size_t delim = endpoint.find(':', 6);

        if (delim != std::string::npos) {
            try {
                return endpoint_t(tcp_endpoint_t(
                    endpoint.substr(6, delim - 6),
                    boost::lexical_cast<uint16_t>(endpoint.substr(delim + 1))
                ));
            } catch (...) {
                throw std::runtime_error("Bad format of tcp endpoint.");
            }

        } else {
            throw std::runtime_error("Bad format of tcp endpoint.");
        }
    } else if (endpoint.compare(0, 7, "unix://") == 0) {
        return endpoint_t(endpoint.substr(7));
    } else {
        throw std::runtime_error("Bad format of tcp endpoint.");
    }
}

bool
endpoint_t::is_unix() const {
    return static_cast<bool>(boost::get<unix_endpoint_t>(&m_value));
}

bool
endpoint_t::is_tcp() const {
    return static_cast<bool>(boost::get<tcp_endpoint_t>(&m_value));
}

const std::string&
endpoint_t::get_host() const {
    return boost::get<tcp_endpoint_t>(m_value).first;
}

uint16_t
endpoint_t::get_port() const {
    return boost::get<tcp_endpoint_t>(m_value).second;
}

const std::string&
endpoint_t::get_path() const {
    return boost::get<unix_endpoint_t>(m_value);
}

namespace {
    struct to_string_visitor :
        public boost::static_visitor<std::string>
    {
        std::string
        operator()(const std::pair<std::string, uint16_t>& e) const {
            return "tcp://" + e.first + ":" + boost::lexical_cast<std::string>(e.second);
        }

        std::string
        operator()(const std::string& e) const {
            return "unix://" + e;
        }
    };
} // namespace

std::string
endpoint_t::to_string() const {
    return boost::apply_visitor(to_string_visitor(), m_value);
}


connection_t::connection_t(boost::asio::io_service& ioservice,
             const endpoint_t& endpoint)
{
    connect(ioservice, endpoint);
}

void
connection_t::connect(boost::asio::io_service& ioservice,
                      const endpoint_t& endpoint)
{
    if (endpoint.is_unix()) {
        auto s = std::make_shared<boost::asio::local::stream_protocol::socket>(ioservice);
        s->connect(boost::asio::local::stream_protocol::endpoint(endpoint.get_path()));
        m_socket = s;
    } else {
        boost::asio::ip::tcp::resolver resolver(ioservice);

        auto it = resolver.resolve(boost::asio::ip::tcp::resolver::query(
            endpoint.get_host(),
            boost::lexical_cast<std::string>(endpoint.get_port())
        ));
        auto end = boost::asio::ip::tcp::resolver::iterator();

        std::exception_ptr error;

        for (; it != end; ++it) {
            auto s = std::make_shared<boost::asio::ip::tcp::socket>(ioservice);
            try {
                s->connect(*it);
                m_socket = s;
                return;
            } catch (...) {
                error = std::current_exception();
            }
        }
        std::rethrow_exception(error);
    }
}

bool
connection_t::is_unix() const {
    return static_cast<bool>(boost::get<std::shared_ptr<unix_socket_t>>(&m_socket));
}

bool
connection_t::is_tcp() const {
    return static_cast<bool>(boost::get<std::shared_ptr<tcp_socket_t>>(&m_socket));
}

std::shared_ptr<connection_t::unix_socket_t>
connection_t::get_unix() const {
    return boost::get<std::shared_ptr<unix_socket_t>>(m_socket);
}

std::shared_ptr<connection_t::tcp_socket_t>
connection_t::get_tcp() const {
    return boost::get<std::shared_ptr<tcp_socket_t>>(m_socket);
}

namespace {

    struct fd_visitor :
        public boost::static_visitor<int>
    {
        int
        operator()(const std::shared_ptr<connection_t::unix_socket_t>& s) const {
            if (!s) {
                throw std::runtime_error("Not connected.");
            }
            return s->native();
        }

        int
        operator()(const std::shared_ptr<connection_t::tcp_socket_t>& s) const {
            if (!s) {
                throw std::runtime_error("Not connected.");
            }
            return s->native();
        }
    };

}

int
connection_t::fd() const {
    return boost::apply_visitor(fd_visitor(), m_socket);
}


namespace {

    curl_socket_t
    open_callback(void* user_data,
                  curlsocktype /* purpose */,
                  curl_sockaddr * /* address */)
    {
        return static_cast<connection_t*>(user_data)->fd();
    }

    int
    sockopt_callback(void * /* user_data */,
                     curl_socket_t /* fd */,
                     curlsocktype /* purpose */)
    {
        return CURL_SOCKOPT_ALREADY_CONNECTED;
    }

    int
    close_callback(void * /* user_data */,
                   curl_socket_t /* fd */)
    {
        return 0;
    }

    std::string
    strip(const char *begin,
          const char *end)
    {
        while (begin < end && isspace(*begin)) {
            ++begin;
        }

        while (begin < end && isspace(*(end - 1))) {
            --end;
        }

        if (begin < end) {
            return std::string(begin, end - begin);
        } else {
            return std::string();
        }
    }

    size_t
    header_callback(const char *header,
                    size_t size,
                    size_t nmemb,
                    void *user_data)
    {
        const char *end = header + size * nmemb;
        const char *delim = std::find(header, end, ':');

        if (delim != end) {
            const char *last_char = std::find(delim, end, '\n');

            std::string field = strip(header, delim);
            std::string value = strip(delim + 1, last_char);

            static_cast<http_response_t*>(user_data)
                ->headers().add_header(std::move(field), std::move(value));
        }

        return size * nmemb;
    }

    size_t
    write_callback(const char *body,
                   size_t size,
                   size_t nmemb,
                   void *user_data)
    {
        static_cast<http_response_t*>(user_data)->body() += std::string(body, size * nmemb);
        return size * nmemb;
    }
}

http_response_t
client_impl_t::request(const http_request_t& request) {
    connection_t socket(m_ioservice_ref, m_endpoint);

    std::string url;
    if (m_endpoint.is_tcp()) {
        url = "http://"
            + m_endpoint.get_host() + ":" + boost::lexical_cast<std::string>(m_endpoint.get_port())
            + request.uri();
    } else {
        url = std::string("http://")
            + "127.0.0.1"
            + request.uri();
    }

    CURL *curl = curl_easy_init();

    if (curl) {
        http_response_t response;

        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);

        curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, &open_callback);
        curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &socket);
        curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, &sockopt_callback);
        curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, &close_callback);
        curl_easy_setopt(curl, CURLOPT_CLOSESOCKETDATA, 0);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

        if (boost::iequals(request.method(), "POST")) {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request.body().data());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, request.body().size());
        } else {
            curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request.method().c_str());
        }

        std::vector<std::string> headers;
        curl_slist *p_headers = NULL;
        for (size_t i = 0; i < request.headers().data().size(); ++i) {
            headers.push_back(
                request.headers().data()[i].first + ": " + request.headers().data()[i].second
            );
            p_headers = curl_slist_append(p_headers, headers.back().c_str());
        }

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, p_headers);

        CURLcode errc = curl_easy_perform(curl);

        int code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        response.set_code(code);

        curl_slist_free_all(p_headers);
        curl_easy_cleanup(curl);

        if (errc != 0) {
            throw std::system_error(errc, std::system_category(), curl_easy_strerror(errc));
        }

        return response;
    } else {
        throw std::runtime_error("Unable to initialize libcurl.");
    }
}

http_response_t
client_impl_t::post(const std::string& uri,
                    const http_headers_t& headers,
                    const rapidjson::Value& body)
{
    http_request_t req("POST", uri, "1.0", headers, "");

    if (!body.IsNull()) {
        rapidjson::GenericStringBuffer<rapidjson::UTF8<>> buffer;
        rapidjson::Writer<rapidjson::GenericStringBuffer<rapidjson::UTF8<>>> writer(buffer);

        body.Accept(writer);

        req.body().assign(buffer.GetString(), buffer.Size());

        req.headers().reset_header("Content-Type", "application/json");
        req.headers().reset_header("Content-Length", boost::lexical_cast<std::string>(buffer.Size()));
    }

    return request(req);
}

http_response_t
client_impl_t::get(const std::string& uri,
                   const http_headers_t& headers)
{
    http_request_t req("GET", uri, "1.0", headers, "");

    return request(req);
}

http_response_t
client_impl_t::del(const std::string& uri,
                   const http_headers_t& headers)
{
    http_request_t req("DELETE", uri, "1.0", headers, "");

    return request(req);
}

connection_t
client_impl_t::request_nobody(http_response_t& response,
                              const http_request_t& request)
{
    connection_t socket(m_ioservice_ref, m_endpoint);

    std::string url;
    if (m_endpoint.is_tcp()) {
        url = "http://"
            + m_endpoint.get_host() + ":" + boost::lexical_cast<std::string>(m_endpoint.get_port())
            + request.uri();
    } else {
        url = std::string("http://")
            + "127.0.0.1"
            + request.uri();
    }

    CURL *curl = curl_easy_init();

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);

        curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, &open_callback);
        curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &socket);
        curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, &sockopt_callback);
        curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, &close_callback);
        curl_easy_setopt(curl, CURLOPT_CLOSESOCKETDATA, 0);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, &header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);

        curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, request.method().c_str());

        std::vector<std::string> headers;
        curl_slist *p_headers = NULL;
        for (size_t i = 0; i < request.headers().data().size(); ++i) {
            headers.push_back(
                request.headers().data()[i].first + ": " + request.headers().data()[i].second
            );
            p_headers = curl_slist_append(p_headers, headers.back().c_str());
        }

        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, p_headers);

        CURLcode errc = curl_easy_perform(curl);

        int code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        response.set_code(code);

        curl_slist_free_all(p_headers);
        curl_easy_cleanup(curl);

        if (errc != 0) {
            throw std::system_error(errc, std::system_category(), curl_easy_strerror(errc));
        }
    } else {
        throw std::runtime_error("Unable to initialize libcurl.");
    }

    return socket;
}

connection_t
client_impl_t::post_nobody(http_response_t& response,
                           const std::string& uri,
                           const http_headers_t& headers)
{
    http_request_t req("POST", uri, "1.0", headers, "");

    return request_nobody(response, req);
}


void
container_t::start(const std::vector<std::string>& binds) {
    rapidjson::Value args;
    rapidjson::Value b;
    rapidjson::Value::AllocatorType allocator;

    b.SetArray();
    for (auto it = binds.begin(); it != binds.end(); ++it) {
        b.PushBack(it->data(), allocator);
    }

    args.SetObject();
    args.AddMember("Binds", b, allocator);

    auto resp = m_client->post(cocaine::format("/containers/%s/start", id()),
                               cocaine::docker::http_headers_t(),
                               args);

    if (!(resp.code() >= 200 && resp.code() < 300)) {
        COCAINE_LOG_WARNING(m_logger,
                            "Unable to start container %s. Docker replied with code %d and body '%s'.",
                            id(),
                            resp.code(),
                            resp.body());
        throw std::runtime_error("Unable to start container " + id() + ".");
    }
}

void
container_t::kill() {
    auto resp = m_client->post(cocaine::format("/containers/%s/kill", id()),
                               cocaine::docker::http_headers_t(),
                               rapidjson::Value());

    if (!(resp.code() >= 200 && resp.code() < 300)) {
        COCAINE_LOG_WARNING(m_logger,
                            "Unable to kill container %s. Docker replied with code %d and body '%s'.",
                            id(),
                            resp.code(),
                            resp.body());
        throw std::runtime_error("Unable to kill container " + id() + ".");
    }
}

void
container_t::stop(unsigned int timeout) {
    auto resp = m_client->post(cocaine::format("/containers/%s/stop?t=%d", id(), timeout),
                               cocaine::docker::http_headers_t(),
                               rapidjson::Value());

    if (!(resp.code() >= 200 && resp.code() < 300)) {
        COCAINE_LOG_WARNING(m_logger,
                            "Unable to stop container %s. Docker replied with code %d and body '%s'.",
                            id(),
                            resp.code(),
                            resp.body());
        throw std::runtime_error("Unable to stop container " + id() + ".");
    }
}

void
container_t::remove(bool volumes) {
    auto resp = m_client->del(cocaine::format("/containers/%s?v=%d", id(), volumes?1:0),
                              cocaine::docker::http_headers_t());

    if (!(resp.code() >= 200 && resp.code() < 300)) {
        COCAINE_LOG_WARNING(m_logger,
                            "Unable to remove container %s. Docker replied with code %d and body '%s'.",
                            id(),
                            resp.code(),
                            resp.body());
        throw std::runtime_error("Unable to remove container " + id() + ".");
    }

    COCAINE_LOG_DEBUG(m_logger,
                      "Container %s has been deleted. Docker replied with code %d and body '%s'.",
                      id(),
                      resp.code(),
                      resp.body());
}

connection_t
container_t::attach() {
    http_response_t resp;
    auto conn = m_client->post_nobody(
        resp,
        cocaine::format("/containers/%s/attach?logs=1&stream=1&stdout=1&stderr=1", id()),
        cocaine::docker::http_headers_t()
    );

    if (!(resp.code() >= 200 && resp.code() < 300)) {
        COCAINE_LOG_WARNING(m_logger,
                            "Unable to attach container %s. Docker replied with code %d and body '%s'.",
                            id(),
                            resp.code(),
                            resp.body());
        throw std::runtime_error("Unable to attach container " + id() + ".");
    }

    return conn;
}

void
client_t::inspect_image(const std::string& image,
                        rapidjson::Document& result)
{
    auto resp = m_client->get(cocaine::format("/images/%s/json", image),
                              cocaine::docker::http_headers_t());

    if (resp.code() >= 200 && resp.code() < 300) {
        result.SetNull();
        result.Parse<0>(resp.body().data());
    } else if (resp.code() >= 400 && resp.code() < 500) {
        result.SetNull();
    } else {
        COCAINE_LOG_WARNING(m_logger,
                            "Unable to inspect an image. Docker replied with code %d and body '%s'.",
                            resp.code(),
                            resp.body());
        throw std::runtime_error("Unable to inspect an image.");
    }
}

void
client_t::pull_image(const std::string& registry,
                     const std::string& image,
                     const std::string& tag)
{
    std::string request = "/images/create?";

    std::pair<std::string, std::string> args[3];
    size_t args_count = 1;

    args[0] = std::pair<std::string, std::string>("fromImage", image);
    if (!registry.empty()) {
        args[args_count] = std::pair<std::string, std::string>("registry", registry);
        ++args_count;
    }
    if (!tag.empty()) {
        args[args_count] = std::pair<std::string, std::string>("tag", tag);
        ++args_count;
    }

    for (size_t i = 0; i < args_count; ++i) {
        if (i == 0) {
            request += args[0].first + "=" + args[0].second;
        } else {
            request += "&" + args[0].first + "=" + args[0].second;
        }
    }

    auto resp = m_client->post(request, cocaine::docker::http_headers_t(), rapidjson::Value());

    if (resp.code() >= 200 && resp.code() < 300) {
        std::string body = resp.body();
        size_t next_object = 0;
        std::vector<std::string> messages;

        // kostyl-way 7 ultimate
        while (true) {
            size_t end = body.find("}{", next_object);

            if (end == std::string::npos) {
                messages.push_back(body.substr(next_object));
                break;
            } else {
                messages.push_back(body.substr(next_object, end + 1 - next_object));
                next_object = end + 1;
            }
        }

        for (auto it = messages.begin(); it != messages.end(); ++it) {
            rapidjson::Document answer;
            answer.Parse<0>(it->data());

            if (answer.HasMember("error")) {
                COCAINE_LOG_ERROR(m_logger,
                                  "Unable to create an image. Docker replied with body: '%s'.",
                                  resp.body());

                throw std::runtime_error("Unable to create an image.");
            }
        }
    } else {
        COCAINE_LOG_ERROR(m_logger,
                          "Unable to create an image. Docker replied with code %d and body '%s'.",
                          resp.code(),
                          resp.body());
        throw std::runtime_error("Unable to create an image.");
    }
}

container_t
client_t::create_container(const rapidjson::Value& args) {
    auto resp = m_client->post("/containers/create", cocaine::docker::http_headers_t(), args);

    if (resp.code() >= 200 && resp.code() < 300) {
        rapidjson::Document answer;
        answer.Parse<0>(resp.body().data());

        if (!answer.HasMember("Id")) {
            COCAINE_LOG_WARNING(m_logger,
                                "Unable to create a container. Id not found in reply from the docker: '%s'.",
                                resp.body());
            throw std::runtime_error("Unable to create a container.");
        }

        if (answer.HasMember("Warnings")) {
            auto& warnings = answer["Warnings"];

            for (auto it = warnings.Begin(); it != warnings.End(); ++it) {
                COCAINE_LOG_WARNING(m_logger,
                                    "Warning from docker: '%s'.",
                                    it->GetString());
            }
        }

        return container_t(answer["Id"].GetString(), m_client, m_logger);
    } else {
        COCAINE_LOG_WARNING(m_logger,
                            "Unable to create a container. Docker replied with code %d and body '%s'.",
                            resp.code(),
                            resp.body());
        throw std::runtime_error("Unable to create a container.");
    }
}
