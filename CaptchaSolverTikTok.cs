using OpenCvSharp;
using System.Text.Json;

public class TikTokCaptchaSolver
{
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<TikTokCaptchaSolver> _logger;
    public TikTokCaptchaSolver(IHttpClientFactory httpClientFactory, ILogger<TikTokCaptchaSolver> logger)
    {
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    private readonly string baseUrl = "https://rc-verification-i18n.tiktokv.com";
    private readonly Dictionary<string, string> _params;

    public TikTokCaptchaSolver(long deviceId, long installId)
    {
        _params = new Dictionary<string, string>
        {
            {"aid", "1233"},
            {"os_type", "0"},
            {"type", "verify"},
            {"subtype", "slide"},
            {"did", deviceId.ToString()},
            {"iid", installId.ToString()},
        };
    }

    public static Mat ProcessImage(byte[] data)
    {
        Mat image = Cv2.ImDecode(data, ImreadModes.Color);
        Mat blurred = new Mat();
        Cv2.CvtColor(image, blurred, ColorConversionCodes.BGR2GRAY);
        Cv2.GaussianBlur(blurred, blurred, new Size(3, 3), 0);
        Mat gradX = new Mat();
        Mat gradY = new Mat();
        Cv2.Sobel(blurred, gradX, MatType.CV_16S, 1, 0, 3);
        Cv2.Sobel(blurred, gradY, MatType.CV_16S, 0, 1, 3);
        Cv2.ConvertScaleAbs(gradX, gradX);
        Cv2.ConvertScaleAbs(gradY, gradY);
        Mat blended = new Mat();
        Cv2.AddWeighted(gradX, 0.5, gradY, 0.5, 0, blended);
        return blended;
    }

    public async Task<string> SolveCaptchaAsync()
    {
        var httpClient = new HttpClient();

        var captchaResponse = await httpClient.GetStringAsync($"{baseUrl}/captcha/get?" + await new FormUrlEncodedContent(_params).ReadAsStringAsync());
        if (string.IsNullOrEmpty(captchaResponse))
        {
            _logger.LogError("Failed To Solve Captcha captchaResponse is null");

            return "";
        }
        using var doc = JsonDocument.Parse(captchaResponse);
        var root = doc.RootElement;

        var puzzleImage = await httpClient.GetByteArrayAsync(root.GetProperty("data").GetProperty("question").GetProperty("url1").GetString());
        var pieceImage = await httpClient.GetByteArrayAsync(root.GetProperty("data").GetProperty("question").GetProperty("url2").GetString());

        Mat puzzle = ProcessImage(puzzleImage);
        Mat piece = ProcessImage(pieceImage);
        await Task.Delay(1000);

        Mat result = new Mat();
        Cv2.MatchTemplate(puzzle, piece, result, TemplateMatchModes.CCoeffNormed);

        double minVal, maxVal;
        Point minLoc, maxLoc;
        result.MinMaxLoc(out minVal, out maxVal, out minLoc, out maxLoc);

        int randlength = new Random().Next(50, 100);

        var replyList = new List<object>();

        for (int i = 0; i < randlength; i++)
        {
            replyList.Add(new
            {
                relative_time = i * randlength,
                x = Math.Round(maxLoc.X / (randlength / (double)(i + 1))),
                y = root.GetProperty("data").GetProperty("question").GetProperty("tip_y").GetInt32()
            });
        }

        var postData = new
        {
            modified_img_width = 552,
            id = root.GetProperty("data").GetProperty("id").GetString(),
            mode = "slide",
            reply = replyList
        };

        return JsonSerializer.Serialize(postData);
    }
}