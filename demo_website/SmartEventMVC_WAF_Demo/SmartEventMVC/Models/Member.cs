using System;
using System.Collections.Generic;

namespace SmartEventMVC.Models;

public partial class Member
{
    public int MemberId { get; set; }

    // Make these nullable if the database can have NULL values
    public string? Mobile { get; set; }
    public string? Password { get; set; }
    public string? Name { get; set; }

    public virtual ICollection<Booking> Bookings { get; set; } = new List<Booking>();
    public virtual ICollection<Review> Reviews { get; set; } = new List<Review>();
}
