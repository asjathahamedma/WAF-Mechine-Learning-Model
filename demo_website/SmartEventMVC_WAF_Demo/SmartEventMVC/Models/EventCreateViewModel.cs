using System.Collections.Generic;

namespace SmartEventMVC.Models
{
    public class EventCreateViewModel
    {
        public Event Event { get; set; }
        public List<SeatTypeInput> SeatTypes { get; set; } = new List<SeatTypeInput>();
    }
}