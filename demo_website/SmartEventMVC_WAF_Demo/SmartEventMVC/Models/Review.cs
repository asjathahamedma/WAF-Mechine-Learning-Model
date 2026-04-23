using System;
using System.Collections.Generic;

namespace SmartEventMVC.Models;

public partial class Review
{
    public int ReviewId { get; set; }

    public int? MemberId { get; set; }

    public int? EventId { get; set; }

    public int? Rating { get; set; }

    public string? Comment { get; set; }

    public virtual Event? Event { get; set; }

    public virtual Member? Member { get; set; }
}
