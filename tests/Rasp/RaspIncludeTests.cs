using System.Collections.Generic;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Shield360.AspNetCore;
using Shield360.Rasp;
using Xunit;

namespace Shield360.Tests.Rasp;

/// <summary>
/// <c>code.include</c> through the explicit <see cref="Shield360Rasp.CheckAssemblyLoad"/>
/// helper (.NET cannot see <c>Assembly.Load*</c> on its own), and the names of a form
/// already read. Port of the include cases of include-hook.test.ts.
/// </summary>
public class RaspIncludeTests : RaspStateTest
{
    private static RaspContext Request(params string[] values)
    {
        var inputs = new List<RaspInput>();
        for (var i = 0; i < values.Length; i++)
        {
            inputs.Add(new RaspInput(values[i], "query.p" + i));
        }

        return new RaspContext(inputs, inRequest: true);
    }

    [Theory]
    [InlineData("plugins/report.dll", "plugins/report.dll")]
    [InlineData("/srv/app/plugins/report.dll", "/srv/app/plugins/report.dll")]
    [InlineData("../report", "/srv/app/plugins/../report.dll")]
    [InlineData("Reports", "Reports")]
    public void Flags_a_name_or_path_from_input(string input, string specifier)
    {
        Assert.Equal("code.include", RaspDetect.Include(specifier, Request(input).InputsSnapshot())?.Rule);
    }

    [Theory]
    [InlineData("report", "/srv/app/plugins/report.dll")]
    [InlineData("pdf", "System.Text.Json")]
    public void Passes_a_fixed_name_or_a_plain_word_inside_the_apps_own_path(string input, string specifier)
    {
        Assert.Null(RaspDetect.Include(specifier, Request(input).InputsSnapshot()));
    }

    [Fact]
    public void CheckAssemblyLoad_blocks_in_block_mode_and_reports_in_monitor()
    {
        var sink = Configure(new EngineSettings(true, "a", RaspMode.Block));
        Assert.Throws<Shield360RaspBlockedException>(() =>
            RaspScope.Run(Request("plugins/report.dll"), () =>
            {
                Shield360Rasp.CheckAssemblyLoad("plugins/report.dll");
                return 0;
            }));
        var e = Assert.Single(sink.Events);
        Assert.Equal("code.include", e.Attrs["shield360.rasp.rule"]);
        Assert.Equal("assembly.load", e.Attrs["shield360.rasp.sink"]);

        sink.Events.Clear();
        RaspScope.Run(Request("report"), () =>
        {
            Shield360Rasp.CheckAssemblyLoad("/srv/app/plugins/report.dll");
            return 0;
        });
        Shield360Rasp.CheckAssemblyLoad("plugins/report.dll"); // no context: nothing to compare
        Assert.Empty(sink.Events);
    }

    [Fact]
    public void Upload_names_come_from_a_form_already_read_and_none_before_it_is()
    {
        var context = new DefaultHttpContext();
        Assert.Null(RaspUploadNames.FromReadForm(context));
        var files = new FormFileCollection { new FormFile(System.IO.Stream.Null, 0, 0, "attachment", "report.pdf") };
        context.Features.Set<IFormFeature>(new FormFeature(new FormCollection(null, files)));
        Assert.Equal(new[] { new RaspUpload("attachment", "report.pdf") }, RaspUploadNames.FromReadForm(context));
    }
}
