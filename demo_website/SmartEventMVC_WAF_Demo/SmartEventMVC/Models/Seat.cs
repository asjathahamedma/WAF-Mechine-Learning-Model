using System;
using System.Collections.Generic;

namespace SmartEventMVC.Models;

public partial class Seat
{
    public int SeatId { get; set; }

    public int? EventId { get; set; }

    public string? SeatNumber { get; set; }

    public string? SeatType { get; set; }
    public bool? IsAvailable { get; set; }

    public decimal Price { get; set; }

    public virtual ICollection<BookingSeat> BookingSeats { get; set; } = new List<BookingSeat>();

    public virtual Event? Event { get; set; }
}
