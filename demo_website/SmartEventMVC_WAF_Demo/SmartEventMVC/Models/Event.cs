using System;
using System.Collections.Generic;

namespace SmartEventMVC.Models;

public partial class Event
{
    public int EventId { get; set; }

    public string? Title { get; set; }

    public string? Description { get; set; }

    public DateOnly? EventDate { get; set; }

    public string? Location { get; set; }

    public string? ImagePath { get; set; }
    public decimal Price { get; set; }
    public virtual ICollection<Booking> Bookings { get; set; } = new List<Booking>();

    public virtual ICollection<Review> Reviews { get; set; } = new List<Review>();

    public virtual ICollection<Seat> Seats { get; set; } = new List<Seat>();
}
